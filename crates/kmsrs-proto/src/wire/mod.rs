//! The DCE/RPC transport the KMS payload rides on.
//!
//! Two layers, and almost all of the detection surface is in the lower one. A
//! KMS host reveals what it is during the bind exchange, before it has been
//! asked to activate anything: the association group it hands out, the port it
//! reports, the padding it emits and the PDU types it will answer are all
//! visible to a passive observer.
//!
//! The GUID wire form is shared with the KMS payload — same mixed-endian
//! layout, same type — so [`crate::kms::layout::WireGuid`] is used here rather
//! than duplicated.

pub mod bind;
pub mod fault;
pub mod header;
pub mod stub;
pub mod syntax;

pub use fault::NcaStatus;
pub use header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
pub use stub::{RequestStub, StubError};
pub use syntax::{FeatureBits, TransferSyntax};
