//! Adapter for `ssz_generic` reference-test fixtures.
//!
//! The generic suite exercises the in-house SSZ codec directly against the
//! consensus-spec vectors rather than against named beacon containers. Each
//! handler names a schema family (booleans, fixed-width integers, basic
//! vectors, bitfields, and a fixed set of test containers), and each case name
//! encodes the concrete schema parameters such as element width or capacity.
//!
//! A `valid` case must decode, re-encode to the exact input bytes, and produce
//! a hash-tree-root equal to `meta.yaml`. An `invalid` case must fail to decode.
//! Re-encoding plus root equality is the accepted gate for valid cases, so the
//! human-readable `value.yaml` is never parsed here.

use std::result::Result as StdResult;

use serde::Deserialize;
use thiserror::Error;

use moonglass_core::primitives::{Root, Uint256};
use moonglass_core::ssz::{
    Bitlist, Bitvector, ContainerDecoder, ContainerEncoder, Deserialize as SszDeserialize,
    DeserializeError, FieldLayout, List, MerkleizationError, Merkleized, Node,
    Serialize as SszSerialize, SerializeError, SimpleSerialize, SszSized, Vector,
    container_is_variable_size, container_size_hint, field_layout, merkleize_roots,
};

use crate::adapters::{Adapter, CaseRunner, Outcome, SupportedHandler, trace_fail, trace_pass};
use crate::error::FixtureError;
use crate::fixtures::{CaseFiles, FixtureFile, decode_fixed_hex, encode_hex};
use crate::inventory::{Case, Runner};

/// Compressed SSZ encoding fixture shared by every generic case.
const SERIALIZED: FixtureFile = FixtureFile::new("serialized.ssz_snappy");
/// Root-bearing metadata fixture present only for valid cases.
const META: FixtureFile = FixtureFile::new("meta.yaml");
/// Upstream suite directory name marking expected-valid cases.
const VALID_SUITE: &str = "valid";

/// Statically registered `ssz_generic` adapter.
pub(super) static ADAPTER: Adapter<SszGeneric> = Adapter::new();

/// Zero-sized runner implementation for the generic SSZ family.
pub(super) struct SszGeneric;

impl CaseRunner for SszGeneric {
    type Handler = GenericHandler;

    const RUNNER: Runner = Runner::SszGeneric;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        run(case, handler)
    }
}

/// `ssz_generic` sidecar parsing result.
type Result<T> = StdResult<T, GenericError>;

/// Error returned while reading `ssz_generic` sidecar fixtures.
#[derive(Debug, Error)]
enum GenericError {
    /// Reading or parsing a fixture file failed.
    #[error(transparent)]
    Fixture(#[from] FixtureError),
    /// Hex decoding of the expected root failed.
    #[error("decode root: {0}")]
    Hex(String),
}

/// Outcome of dispatching one generic case to a concrete Rust type.
///
/// A schema parameter the in-house types do not instantiate (for example a
/// zero-length vector) yields [`Self::Unsupported`] so the caller can surface it
/// without claiming a pass or a failure.
enum CaseOutcome {
    /// The case ran against a concrete type and produced an outcome.
    Ran(Outcome),
    /// The schema parameter has no in-house type to dispatch to.
    Unsupported(String),
}

/// Root parsed from a valid case's `meta.yaml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    /// Expected hash-tree-root in `0x`-prefixed hex.
    root: String,
}

/// One generic handler family and its case-name dispatcher.
#[derive(Clone, Copy)]
pub(super) struct GenericHandler {
    /// Upstream handler directory name.
    name: &'static str,
    /// Dispatch a case in this handler given its parsed schema parameters.
    dispatch: fn(case_name: &str, &[u8], Option<Root>, bool) -> CaseOutcome,
}

impl GenericHandler {
    /// Build a handler entry.
    const fn new(
        name: &'static str,
        dispatch: fn(&str, &[u8], Option<Root>, bool) -> CaseOutcome,
    ) -> Self {
        Self { name, dispatch }
    }

    /// Dispatch one case to its concrete type.
    fn dispatch(
        self,
        case_name: &str,
        bytes: &[u8],
        meta_root: Option<Root>,
        valid: bool,
    ) -> CaseOutcome {
        (self.dispatch)(case_name, bytes, meta_root, valid)
    }
}

impl SupportedHandler for GenericHandler {
    const ALL: &'static [Self] = &[
        Self::new("boolean", dispatch_boolean),
        Self::new("uints", dispatch_uints),
        Self::new("basic_vector", dispatch_basic_vector),
        Self::new("bitlist", dispatch_bitlist),
        Self::new("bitvector", dispatch_bitvector),
        Self::new("containers", dispatch_containers),
    ];

    fn as_str(self) -> &'static str {
        self.name
    }
}

/// Whether a case is a progressive-container vector under the `containers`
/// handler.
///
/// The upstream `containers` directory mixes the basic test containers with
/// progressive containers whose roots use a merkleization scheme the in-house
/// SSZ does not implement. Discovery skips these so the remaining basic-container
/// cases can run as a supported family.
pub(super) fn is_progressive_container_case(case: &Case) -> bool {
    case.kind.runner == Runner::SszGeneric
        && case.kind.handler.as_str() == "containers"
        && case.id.starts_with("Progressive")
}

fn run(case: &Case, handler: GenericHandler) -> Outcome {
    let files = CaseFiles::new(case);
    let valid = case.suite == VALID_SUITE;
    let meta_root = if valid {
        match read_meta_root(files) {
            Ok(root) => {
                trace_pass("ssz_generic meta", "read expected root");
                Some(root)
            }
            Err(e) => {
                let detail = format!("read meta.yaml: {e:#}");
                trace_fail("ssz_generic meta", &detail);
                return Outcome::Fail(detail);
            }
        }
    } else {
        None
    };
    let bytes = match files.read_snappy(SERIALIZED) {
        Ok(b) => {
            trace_pass(
                "ssz_generic serialized",
                format_args!("decoded {} bytes", b.len()),
            );
            b
        }
        Err(e) => {
            let detail = format!("snappy decode: {e:#}");
            trace_fail("ssz_generic serialized", &detail);
            return Outcome::Fail(detail);
        }
    };
    match handler.dispatch(&case.id, &bytes, meta_root, valid) {
        CaseOutcome::Ran(outcome) => outcome,
        CaseOutcome::Unsupported(detail) => {
            trace_fail("ssz_generic dispatch", &detail);
            Outcome::Fail(detail)
        }
    }
}

fn read_meta_root(files: CaseFiles) -> Result<Root> {
    let meta: Meta = files.read_yaml(META)?;
    let bytes = decode_fixed_hex(&meta.root).map_err(|e| GenericError::Hex(e.to_string()))?;
    Ok(Root(bytes))
}

/// Match a runtime length against a literal list, dispatching to a generic arm.
///
/// Each literal expands `$arm!(literal)` so the concrete const-generic type is
/// chosen at compile time. A length outside the list is reported as unsupported
/// rather than failed, since the in-house types only instantiate the lengths the
/// upstream vectors exercise.
macro_rules! dispatch_len {
    ($n:expr, $arm:ident, $($len:literal),+ $(,)?) => {
        match $n {
            $( $len => $arm!($len), )+
            other => CaseOutcome::Unsupported(format!("unsupported length {other}")),
        }
    };
}

/// Run one valid or invalid case against a concrete SSZ type.
///
/// Valid cases must round-trip the bytes exactly and match the expected root.
/// Invalid cases must fail to decode.
fn run_case<T>(bytes: &[u8], meta_root: Option<Root>, valid: bool) -> Outcome
where
    T: SszDeserialize + SszSerialize + Merkleized,
{
    let decoded = T::deserialize(bytes);
    if !valid {
        return match decoded {
            Ok(_) => {
                let detail = "expected decode failure, value decoded".to_owned();
                trace_fail("ssz_generic invalid", &detail);
                Outcome::Fail(detail)
            }
            Err(e) => {
                trace_pass(
                    "ssz_generic invalid",
                    format_args!("rejected as expected: {e}"),
                );
                Outcome::Pass
            }
        };
    }
    let value = match decoded {
        Ok(v) => {
            trace_pass("ssz_generic decode", "decoded value");
            v
        }
        Err(e) => {
            let detail = format!("ssz decode: {e}");
            trace_fail("ssz_generic decode", &detail);
            return Outcome::Fail(detail);
        }
    };
    let mut reencoded = Vec::with_capacity(bytes.len());
    if let Err(e) = SszSerialize::serialize(&value, &mut reencoded) {
        let detail = format!("ssz re-encode: {e}");
        trace_fail("ssz_generic re-encode", &detail);
        return Outcome::Fail(detail);
    }
    if reencoded != bytes {
        let detail = format!(
            "ssz re-encode mismatch: got {} bytes, want {} bytes",
            reencoded.len(),
            bytes.len()
        );
        trace_fail("ssz_generic re-encode", &detail);
        return Outcome::Fail(detail);
    }
    trace_pass(
        "ssz_generic re-encode",
        format_args!("{} bytes", reencoded.len()),
    );
    let node = match Merkleized::hash_tree_root(&value) {
        Ok(r) => {
            trace_pass("ssz_generic hash_tree_root", "computed root");
            r
        }
        Err(e) => {
            let detail = format!("hash_tree_root: {e}");
            trace_fail("ssz_generic hash_tree_root", &detail);
            return Outcome::Fail(detail);
        }
    };
    let Some(expected) = meta_root else {
        let detail = "valid case missing expected root".to_owned();
        trace_fail("ssz_generic root", &detail);
        return Outcome::Fail(detail);
    };
    let got = Root::from(node);
    if got == expected {
        trace_pass("ssz_generic root", "root matches meta.yaml");
        Outcome::Pass
    } else {
        let detail = format!(
            "root mismatch: got 0x{}, want 0x{}",
            encode_hex(&got.0),
            encode_hex(&expected.0)
        );
        trace_fail("ssz_generic root", &detail);
        Outcome::Fail(detail)
    }
}

/// Outcome for a zero-length vector or bitvector schema.
///
/// SSZ forbids zero-length vectors and bitvectors, so the type itself is illegal
/// and there is no in-house type to instantiate. Every such case is therefore an
/// expected rejection: the case passes when it is an invalid-suite case and fails
/// if the upstream vectors ever mark one valid.
fn reject_illegal_zero_length(valid: bool) -> Outcome {
    if valid {
        let detail = "zero-length vector or bitvector marked valid".to_owned();
        trace_fail("ssz_generic invalid", &detail);
        Outcome::Fail(detail)
    } else {
        trace_pass(
            "ssz_generic invalid",
            "zero-length type rejected as expected",
        );
        Outcome::Pass
    }
}

/// Report a case whose schema could not be parsed from its name.
fn unparsed(case_name: &str) -> CaseOutcome {
    CaseOutcome::Unsupported(format!(
        "could not parse schema from case name '{case_name}'"
    ))
}

/// Dispatch a parsed-and-supported case to the generic worker.
fn ran<T>(bytes: &[u8], meta_root: Option<Root>, valid: bool) -> CaseOutcome
where
    T: SszDeserialize + SszSerialize + Merkleized,
{
    CaseOutcome::Ran(run_case::<T>(bytes, meta_root, valid))
}

fn dispatch_boolean(
    _case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    ran::<bool>(bytes, meta_root, valid)
}

fn dispatch_uints(
    case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    let Some(bits) = parse_field(case_name, "uint") else {
        return unparsed(case_name);
    };
    match bits {
        8 => ran::<u8>(bytes, meta_root, valid),
        16 => ran::<u16>(bytes, meta_root, valid),
        32 => ran::<u32>(bytes, meta_root, valid),
        64 => ran::<u64>(bytes, meta_root, valid),
        128 => ran::<u128>(bytes, meta_root, valid),
        256 => ran::<Uint256>(bytes, meta_root, valid),
        other => CaseOutcome::Unsupported(format!("unsupported uint width {other}")),
    }
}

/// Parse a basic-vector case name of the form `vec_<elem>_<len>_...`.
fn parse_vector_schema(case_name: &str) -> Option<(&str, usize)> {
    let mut parts = case_name.split('_');
    (parts.next()? == "vec").then_some(())?;
    let elem = parts.next()?;
    let len = parts.next()?.parse::<usize>().ok()?;
    Some((elem, len))
}

/// Dispatch a `basic_vector` case named `vec_<elem>_<len>_...`.
fn dispatch_basic_vector(
    case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    let Some((elem, len)) = parse_vector_schema(case_name) else {
        return unparsed(case_name);
    };
    dispatch_vector_elem(elem, len, bytes, meta_root, valid)
}

/// Match the element type for a basic vector, then dispatch on its length.
fn dispatch_vector_elem(
    elem: &str,
    len: usize,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    if len == 0 {
        return CaseOutcome::Ran(reject_illegal_zero_length(valid));
    }
    macro_rules! vector_arm {
        ($len:literal) => {
            match elem {
                "bool" => ran::<Vector<bool, $len>>(bytes, meta_root, valid),
                "uint8" => ran::<Vector<u8, $len>>(bytes, meta_root, valid),
                "uint16" => ran::<Vector<u16, $len>>(bytes, meta_root, valid),
                "uint32" => ran::<Vector<u32, $len>>(bytes, meta_root, valid),
                "uint64" => ran::<Vector<u64, $len>>(bytes, meta_root, valid),
                "uint128" => ran::<Vector<u128, $len>>(bytes, meta_root, valid),
                "uint256" => ran::<Vector<Uint256, $len>>(bytes, meta_root, valid),
                other => CaseOutcome::Unsupported(format!("unsupported vector element {other}")),
            }
        };
    }
    dispatch_len!(len, vector_arm, 1, 2, 3, 4, 5, 8, 16, 31, 512, 513)
}

/// Dispatch a `bitlist` case named `bitlist_<N>_...`.
fn dispatch_bitlist(
    case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    let Some(limit) = parse_field(case_name, "bitlist") else {
        return unparsed(case_name);
    };
    macro_rules! bitlist_arm {
        ($n:literal) => {
            ran::<Bitlist<$n>>(bytes, meta_root, valid)
        };
    }
    dispatch_len!(
        limit,
        bitlist_arm,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        15,
        16,
        17,
        31,
        32,
        33,
        511,
        512,
        513
    )
}

/// Dispatch a `bitvector` case named `bitvec_<N>_...`.
fn dispatch_bitvector(
    case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    let Some(len) = parse_field(case_name, "bitvec") else {
        return unparsed(case_name);
    };
    if len == 0 {
        return CaseOutcome::Ran(reject_illegal_zero_length(valid));
    }
    macro_rules! bitvector_arm {
        ($n:literal) => {
            ran::<Bitvector<$n>>(bytes, meta_root, valid)
        };
    }
    dispatch_len!(
        len,
        bitvector_arm,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        15,
        16,
        17,
        31,
        32,
        33,
        511,
        512,
        513
    )
}

/// Dispatch a `containers` case whose name starts with a struct type name.
fn dispatch_containers(
    case_name: &str,
    bytes: &[u8],
    meta_root: Option<Root>,
    valid: bool,
) -> CaseOutcome {
    if case_name.starts_with("SingleFieldTestStruct") {
        ran::<SingleFieldTestStruct>(bytes, meta_root, valid)
    } else if case_name.starts_with("SmallTestStruct") {
        ran::<SmallTestStruct>(bytes, meta_root, valid)
    } else if case_name.starts_with("FixedTestStruct") {
        ran::<FixedTestStruct>(bytes, meta_root, valid)
    } else if case_name.starts_with("VarTestStruct") {
        ran::<VarTestStruct>(bytes, meta_root, valid)
    } else if case_name.starts_with("ComplexTestStruct") {
        ran::<ComplexTestStruct>(bytes, meta_root, valid)
    } else if case_name.starts_with("BitsStruct") {
        ran::<BitsStruct>(bytes, meta_root, valid)
    } else {
        CaseOutcome::Unsupported(format!("unsupported container type for case '{case_name}'"))
    }
}

/// Parse the numeric parameter from a case name of the form `<prefix>_<n>_...`.
fn parse_field(case_name: &str, prefix: &str) -> Option<usize> {
    case_name
        .strip_prefix(prefix)?
        .strip_prefix('_')?
        .split('_')
        .next()?
        .parse::<usize>()
        .ok()
}

/// `ssz_generic` container with a single basic field.
#[derive(Debug, PartialEq, Eq)]
struct SingleFieldTestStruct {
    /// Sole `uint8` field.
    a: u8,
}

/// `ssz_generic` container with two basic fields.
#[derive(Debug, PartialEq, Eq)]
struct SmallTestStruct {
    /// First `uint16` field.
    a: u16,
    /// Second `uint16` field.
    b: u16,
}

/// `ssz_generic` fixed-size container with three basic fields.
#[derive(Debug, PartialEq, Eq)]
struct FixedTestStruct {
    /// `uint8` field.
    a: u8,
    /// `uint64` field.
    b: u64,
    /// `uint32` field.
    c: u32,
}

/// `ssz_generic` variable-size container with one list field.
#[derive(Debug, PartialEq, Eq)]
struct VarTestStruct {
    /// Leading `uint16` field.
    a: u16,
    /// Bounded `uint16` list field.
    b: List<u16, 1024>,
    /// Trailing `uint8` field.
    c: u8,
}

/// `ssz_generic` container mixing fixed and variable fields and nested structs.
#[derive(Debug, PartialEq, Eq)]
struct ComplexTestStruct {
    /// Leading `uint16` field.
    a: u16,
    /// Bounded `uint16` list field.
    b: List<u16, 128>,
    /// Fixed `uint8` field.
    c: u8,
    /// Bounded byte list field.
    d: List<u8, 256>,
    /// Nested variable-size container.
    e: VarTestStruct,
    /// Fixed-length vector of fixed-size containers.
    f: Vector<FixedTestStruct, 4>,
    /// Fixed-length vector of variable-size containers.
    g: Vector<VarTestStruct, 2>,
}

/// `ssz_generic` container exercising bitfield fields.
#[derive(Debug, PartialEq, Eq)]
struct BitsStruct {
    /// Bounded bitlist field.
    a: Bitlist<5>,
    /// Fixed bitvector field.
    b: Bitvector<2>,
    /// Single-bit bitvector field.
    c: Bitvector<1>,
    /// Bounded bitlist field.
    d: Bitlist<6>,
    /// Byte-wide bitvector field.
    e: Bitvector<8>,
}

/// Field layout for [`SingleFieldTestStruct`].
fn single_field_test_struct_layout() -> [FieldLayout; 1] {
    [field_layout::<u8>()]
}

impl SszSized for SingleFieldTestStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&single_field_test_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&single_field_test_struct_layout())
    }
}

impl SszSerialize for SingleFieldTestStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for SingleFieldTestStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &single_field_test_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<u8>()?,
        })
    }
}

impl Merkleized for SingleFieldTestStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[Merkleized::hash_tree_root(&self.a)?]))
    }
}

impl SimpleSerialize for SingleFieldTestStruct {
    fn is_composite_type() -> bool {
        true
    }
}

/// Field layout for [`SmallTestStruct`].
fn small_test_struct_layout() -> [FieldLayout; 2] {
    [field_layout::<u16>(), field_layout::<u16>()]
}

impl SszSized for SmallTestStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&small_test_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&small_test_struct_layout())
    }
}

impl SszSerialize for SmallTestStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.write_field(&self.b)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for SmallTestStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &small_test_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<u16>()?,
            b: decoder.deserialize_next::<u16>()?,
        })
    }
}

impl Merkleized for SmallTestStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[
            Merkleized::hash_tree_root(&self.a)?,
            Merkleized::hash_tree_root(&self.b)?,
        ]))
    }
}

impl SimpleSerialize for SmallTestStruct {
    fn is_composite_type() -> bool {
        true
    }
}

/// Field layout for [`FixedTestStruct`].
fn fixed_test_struct_layout() -> [FieldLayout; 3] {
    [
        field_layout::<u8>(),
        field_layout::<u64>(),
        field_layout::<u32>(),
    ]
}

impl SszSized for FixedTestStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&fixed_test_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&fixed_test_struct_layout())
    }
}

impl SszSerialize for FixedTestStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.write_field(&self.b)?;
        encoder.write_field(&self.c)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for FixedTestStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &fixed_test_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<u8>()?,
            b: decoder.deserialize_next::<u64>()?,
            c: decoder.deserialize_next::<u32>()?,
        })
    }
}

impl Merkleized for FixedTestStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[
            Merkleized::hash_tree_root(&self.a)?,
            Merkleized::hash_tree_root(&self.b)?,
            Merkleized::hash_tree_root(&self.c)?,
        ]))
    }
}

impl SimpleSerialize for FixedTestStruct {
    fn is_composite_type() -> bool {
        true
    }
}

/// Field layout for [`VarTestStruct`].
fn var_test_struct_layout() -> [FieldLayout; 3] {
    [
        field_layout::<u16>(),
        field_layout::<List<u16, 1024>>(),
        field_layout::<u8>(),
    ]
}

impl SszSized for VarTestStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&var_test_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&var_test_struct_layout())
    }
}

impl SszSerialize for VarTestStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.write_field(&self.b)?;
        encoder.write_field(&self.c)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for VarTestStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &var_test_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<u16>()?,
            b: decoder.deserialize_next::<List<u16, 1024>>()?,
            c: decoder.deserialize_next::<u8>()?,
        })
    }
}

impl Merkleized for VarTestStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[
            Merkleized::hash_tree_root(&self.a)?,
            Merkleized::hash_tree_root(&self.b)?,
            Merkleized::hash_tree_root(&self.c)?,
        ]))
    }
}

impl SimpleSerialize for VarTestStruct {
    fn is_composite_type() -> bool {
        true
    }
}

/// Field layout for [`ComplexTestStruct`].
fn complex_test_struct_layout() -> [FieldLayout; 7] {
    [
        field_layout::<u16>(),
        field_layout::<List<u16, 128>>(),
        field_layout::<u8>(),
        field_layout::<List<u8, 256>>(),
        field_layout::<VarTestStruct>(),
        field_layout::<Vector<FixedTestStruct, 4>>(),
        field_layout::<Vector<VarTestStruct, 2>>(),
    ]
}

impl SszSized for ComplexTestStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&complex_test_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&complex_test_struct_layout())
    }
}

impl SszSerialize for ComplexTestStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.write_field(&self.b)?;
        encoder.write_field(&self.c)?;
        encoder.write_field(&self.d)?;
        encoder.write_field(&self.e)?;
        encoder.write_field(&self.f)?;
        encoder.write_field(&self.g)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for ComplexTestStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &complex_test_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<u16>()?,
            b: decoder.deserialize_next::<List<u16, 128>>()?,
            c: decoder.deserialize_next::<u8>()?,
            d: decoder.deserialize_next::<List<u8, 256>>()?,
            e: decoder.deserialize_next::<VarTestStruct>()?,
            f: decoder.deserialize_next::<Vector<FixedTestStruct, 4>>()?,
            g: decoder.deserialize_next::<Vector<VarTestStruct, 2>>()?,
        })
    }
}

impl Merkleized for ComplexTestStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[
            Merkleized::hash_tree_root(&self.a)?,
            Merkleized::hash_tree_root(&self.b)?,
            Merkleized::hash_tree_root(&self.c)?,
            Merkleized::hash_tree_root(&self.d)?,
            Merkleized::hash_tree_root(&self.e)?,
            Merkleized::hash_tree_root(&self.f)?,
            Merkleized::hash_tree_root(&self.g)?,
        ]))
    }
}

impl SimpleSerialize for ComplexTestStruct {
    fn is_composite_type() -> bool {
        true
    }
}

/// Field layout for [`BitsStruct`].
fn bits_struct_layout() -> [FieldLayout; 5] {
    [
        field_layout::<Bitlist<5>>(),
        field_layout::<Bitvector<2>>(),
        field_layout::<Bitvector<1>>(),
        field_layout::<Bitlist<6>>(),
        field_layout::<Bitvector<8>>(),
    ]
}

impl SszSized for BitsStruct {
    fn is_variable_size() -> bool {
        container_is_variable_size(&bits_struct_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&bits_struct_layout())
    }
}

impl SszSerialize for BitsStruct {
    fn serialize(&self, buffer: &mut Vec<u8>) -> StdResult<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.a)?;
        encoder.write_field(&self.b)?;
        encoder.write_field(&self.c)?;
        encoder.write_field(&self.d)?;
        encoder.write_field(&self.e)?;
        encoder.finish(buffer)
    }
}

impl SszDeserialize for BitsStruct {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &bits_struct_layout())?;
        Ok(Self {
            a: decoder.deserialize_next::<Bitlist<5>>()?,
            b: decoder.deserialize_next::<Bitvector<2>>()?,
            c: decoder.deserialize_next::<Bitvector<1>>()?,
            d: decoder.deserialize_next::<Bitlist<6>>()?,
            e: decoder.deserialize_next::<Bitvector<8>>()?,
        })
    }
}

impl Merkleized for BitsStruct {
    fn hash_tree_root(&self) -> StdResult<Node, MerkleizationError> {
        Ok(merkleize_roots(&[
            Merkleized::hash_tree_root(&self.a)?,
            Merkleized::hash_tree_root(&self.b)?,
            Merkleized::hash_tree_root(&self.c)?,
            Merkleized::hash_tree_root(&self.d)?,
            Merkleized::hash_tree_root(&self.e)?,
        ]))
    }
}

impl SimpleSerialize for BitsStruct {
    fn is_composite_type() -> bool {
        true
    }
}
