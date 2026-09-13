//! Platform v1 responses. These are wire data, never authorization proofs.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    TenantCreated,
    AdministratorAdded,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Operation {
    pub operation_id: Uuid,
    pub kind: OperationKind,
    pub tenant_id: String,
    pub principal_id: Uuid,
    pub created_at: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationReply {
    pub operation: Operation,
    pub active: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
    pub initial_principal_id: Uuid,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct TenantPage {
    pub tenants: Vec<Tenant>,
    pub next_cursor: Option<String>,
}
