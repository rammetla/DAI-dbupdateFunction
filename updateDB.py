"""
Azure SQL Server Approval Handler
Processes Teams approval callbacks and updates patient discharge database.

RESPONSIBILITIES:
1. Receives Teams approval callbacks (Mark as Complete / In Progress)
2. Updates Azure SQL Server database with approval status
3. Only updates HITL fields: PhysicianClearanceFlag, PTSummaryDone, TransportReady
4. Maintains audit trail for compliance

DESIGN PRINCIPLES:
- Fire-and-forget pattern: process approval and update DB immediately
- Idempotent: safe to retry without side effects
- Type-safe: use Pydantic models for validation
- Parameterized SQL queries: prevent SQL injection
- Comprehensive logging: audit trail for all updates
"""

import json
import logging
import os
from typing import Any, Dict, Optional
from datetime import datetime
import pyodbc
from pydantic import BaseModel, Field, validator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# DATA MODELS
# ============================================================================

class TeamsApprovalPayload(BaseModel):
    """
    Teams approval callback payload.
    Sent when user clicks "Mark as Complete" or "In Progress" button.
    """
    patient_id: str = Field(..., description="Patient identifier (e.g., P003)")
    domain: str = Field(..., description="Domain: medical, clinical, or care_coordination")
    correlation_id: str = Field(..., description="Correlation ID linking approval to request (e.g., P003_medical)")
    action: str = Field(..., description="Action: complete or in_progress")
    approver_email: str = Field(..., description="Email of the approver")
    approver_name: Optional[str] = Field(default=None, description="Name of the approver")
    approved_timestamp: str = Field(..., description="ISO format timestamp of approval")
    
    @validator('domain')
    def validate_domain(cls, v):
        valid_domains = ['medical', 'clinical', 'care_coordination']
        if v.lower() not in valid_domains:
            raise ValueError(f"Domain must be one of {valid_domains}")
        return v.lower()
    
    @validator('action')
    def validate_action(cls, v):
        valid_actions = ['complete', 'in_progress']
        if v.lower() not in valid_actions:
            raise ValueError(f"Action must be one of {valid_actions}")
        return v.lower()


class ApprovalResult(BaseModel):
    """Response from approval update operation."""
    status: str = Field(..., description="success or failure")
    patient_id: str = Field(..., description="Patient ID that was updated")
    domain: str = Field(..., description="Domain that was approved")
    action_taken: str = Field(..., description="approved or acknowledged")
    field_updated: Optional[str] = Field(default=None, description="Database field that was updated")
    message: str = Field(..., description="Status message")
    timestamp: str = Field(..., description="UTC timestamp of operation")


# ============================================================================
# DOMAIN TO DATABASE FIELD MAPPING
# ============================================================================

DOMAIN_FIELD_MAPPING = {
    "medical": "PhysicianClearanceFlag",
    "clinical": "PTSummaryDone",
    "care_coordination": "TransportReady"
}


# ============================================================================
# DATABASE CONNECTION HANDLER
# ============================================================================

class AzureSQLHandler:
    """Handle Azure SQL Server connections and operations."""
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize Azure SQL handler.
        
        Args:
            connection_string: Azure SQL connection string. If not provided,
                             reads from AZURE_SQL_CONNECTION_STRING environment variable.
        """
        self.connection_string = connection_string or os.getenv("AZURE_SQL_CONNECTION_STRING")
        if not self.connection_string:
            raise ValueError("AZURE_SQL_CONNECTION_STRING environment variable not set")
        logger.info("Azure SQL handler initialized")
    
    def get_connection(self):
        """
        Get a new database connection.
        
        Returns:
            pyodbc connection object
            
        Raises:
            pyodbc.Error: If connection fails
        """
        try:
            conn = pyodbc.connect(self.connection_string)
            conn.setencoding(encoding='utf-8')
            logger.debug("Database connection established")
            return conn
        except pyodbc.Error as e:
            logger.error(f"Failed to connect to Azure SQL: {str(e)}")
            raise
    
    def update_patient_approval(
        self,
        patient_id: str,
        field_to_update: str,
        approver_email: str,
        approval_timestamp: str
    ) -> Dict[str, Any]:
        """
        Update patient discharge record with approval.
        
        Args:
            patient_id: Patient identifier
            field_to_update: Database field name (PhysicianClearanceFlag, PTSummaryDone, TransportReady)
            approver_email: Email of the approver
            approval_timestamp: ISO format timestamp of approval
            
        Returns:
            Dictionary with update status
            
        Raises:
            ValueError: If field name is invalid
            pyodbc.Error: If database update fails
        """
        # Validate field name (security: prevent SQL injection)
        valid_fields = list(DOMAIN_FIELD_MAPPING.values())
        if field_to_update not in valid_fields:
            raise ValueError(f"Invalid field name: {field_to_update}")
        
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Prepare parameterized SQL query
            current_utc = datetime.utcnow().isoformat()
            
            # Build update query with parameterized values (prevent SQL injection)
            update_query = f"""
            UPDATE [dbo].[PatientDischarge]
            SET 
                [{field_to_update}] = 1,
                [LastUpdated] = ?,
                [ApprovedBy_{field_to_update}] = ?,
                [ApprovedAt_{field_to_update}] = ?
            WHERE [PatientID] = ?
            """
            
            logger.info(f"Executing update query for patient {patient_id}, field {field_to_update}")
            
            # Execute with parameterized query
            cursor.execute(
                update_query,
                (current_utc, approver_email, approval_timestamp, patient_id)
            )
            
            # Get rows affected
            rows_affected = cursor.rowcount
            
            if rows_affected == 0:
                logger.warning(f"No rows updated for patient {patient_id}. Patient may not exist.")
                conn.rollback()
                return {
                    "status": "failure",
                    "patient_id": patient_id,
                    "field": field_to_update,
                    "rows_affected": 0,
                    "message": f"Patient {patient_id} not found in database"
                }
            
            # Commit transaction
            conn.commit()
            logger.info(f"Successfully updated {field_to_update} for patient {patient_id}")
            
            return {
                "status": "success",
                "patient_id": patient_id,
                "field": field_to_update,
                "rows_affected": rows_affected,
                "message": f"Successfully updated {field_to_update} = 1 for patient {patient_id}"
            }
            
        except pyodbc.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error updating patient {patient_id}: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()
                logger.debug("Database connection closed")
    
    def log_approval_audit(
        self,
        patient_id: str,
        domain: str,
        action: str,
        approver_email: str,
        timestamp: str
    ) -> None:
        """
        Log approval action to audit table (optional).
        
        Args:
            patient_id: Patient identifier
            domain: Approval domain
            action: Action taken (complete or in_progress)
            approver_email: Email of approver
            timestamp: Action timestamp
        """
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Insert audit log for
            audit_query = """
            INSERT INTO [dbo].[ApprovalAudit]
            ([PatientID], [Domain], [Action], [ApproverEmail], [ApprovalTimestamp], [CreatedAt])
            VALUES (?, ?, ?, ?, ?, ?)
            """
            
            created_at = datetime.utcnow().isoformat()
            cursor.execute(
                audit_query,
                (patient_id, domain, action, approver_email, timestamp, created_at)
            )
            
            conn.commit()
            logger.info(f"Logged approval audit for patient {patient_id}, domain {domain}")
            
        except pyodbc.Error as e:
            logger.warning(f"Failed to log audit (non-critical): {str(e)}")
            # Don't raise - logging audit is non-critical
        finally:
            if conn:
                conn.close()


# ============================================================================
# MAIN APPROVAL HANDLER FUNCTION
# ============================================================================

def update_patient_on_approval(
    payload: Dict[str, Any],
    connection_string: Optional[str] = None
) -> ApprovalResult:
    """
    Process Teams approval callback and update patient database.
    
    ACTIONS:
    - "complete": Updates HITL field to 1 (True) indicating approval
    - "in_progress": Logs acknowledgment without updating field (still pending)
    
    Args:
        payload: Teams approval callback payload with:
                - patient_id: Patient identifier
                - domain: medical|clinical|care_coordination
                - correlation_id: PatientID_Domain
                - action: complete|in_progress
                - approver_email: Email of approver
                - approver_name: Name of approver (optional)
                - approved_timestamp: ISO format timestamp
        
        connection_string: Azure SQL connection string (optional).
                         If not provided, uses AZURE_SQL_CONNECTION_STRING env var.
    
    Returns:
        ApprovalResult: Status of update operation
        
    Raises:
        ValueError: If payload is invalid
        pyodbc.Error: If database operation fails
    """
    
    try:
        # Validate payload
        approval = TeamsApprovalPayload(**payload)
        logger.info(f"Processing approval callback: patient={approval.patient_id}, domain={approval.domain}, action={approval.action}")
        
        # Extract domain from correlation_id (format: PatientID_Domain)
        domain = approval.domain.lower()
        
        # Get the field to update
        field_to_update = DOMAIN_FIELD_MAPPING.get(domain)
        if not field_to_update:
            logger.error(f"Unknown domain: {domain}")
            return ApprovalResult(
                status="failure",
                patient_id=approval.patient_id,
                domain=domain,
                action_taken="error",
                field_updated=None,
                message=f"Unknown domain: {domain}",
                timestamp=datetime.utcnow().isoformat()
            )
        
        # Initialize database handler
        db_handler = AzureSQLHandler(connection_string)
        
        # Handle based on action
        if approval.action == "complete":
            logger.info(f"Mark as Complete: Updating {field_to_update} for patient {approval.patient_id}")
            
            # Update database field
            update_result = db_handler.update_patient_approval(
                patient_id=approval.patient_id,
                field_to_update=field_to_update,
                approver_email=approval.approver_email,
                approval_timestamp=approval.approved_timestamp
            )
            
            if update_result["status"] == "success":
                # Log to audit trail
                db_handler.log_approval_audit(
                    patient_id=approval.patient_id,
                    domain=domain,
                    action="approved",
                    approver_email=approval.approver_email,
                    timestamp=approval.approved_timestamp
                )
                
                logger.info(f"✓ Approval APPROVED for patient {approval.patient_id}, domain {domain}")
                return ApprovalResult(
                    status="success",
                    patient_id=approval.patient_id,
                    domain=domain,
                    action_taken="approved",
                    field_updated=field_to_update,
                    message=f"Successfully set {field_to_update} = 1 for patient {approval.patient_id}",
                    timestamp=datetime.utcnow().isoformat()
                )
            else:
                logger.error(f"Database update failed: {update_result.get('message')}")
                return ApprovalResult(
                    status="failure",
                    patient_id=approval.patient_id,
                    domain=domain,
                    action_taken="error",
                    field_updated=None,
                    message=update_result.get("message", "Database update failed"),
                    timestamp=datetime.utcnow().isoformat()
                )
        
        elif approval.action == "in_progress":
            logger.info(f"In Progress: Acknowledgment for patient {approval.patient_id}, domain {domain}")
            
            # Log acknowledgment only (don't update field)
            db_handler.log_approval_audit(
                patient_id=approval.patient_id,
                domain=domain,
                action="acknowledged_in_progress",
                approver_email=approval.approver_email,
                timestamp=approval.approved_timestamp
            )
            
            logger.info(f"◐ Approval IN PROGRESS acknowledgment for patient {approval.patient_id}, domain {domain}")
            return ApprovalResult(
                status="success",
                patient_id=approval.patient_id,
                domain=domain,
                action_taken="acknowledged",
                field_updated=None,
                message=f"Acknowledged in-progress status for patient {approval.patient_id}, domain {domain}. Field {field_to_update} remains pending.",
                timestamp=datetime.utcnow().isoformat()
            )
        
        else:
            raise ValueError(f"Unexpected action: {approval.action}")
    
    except Exception as e:
        logger.error(f"Error processing approval: {str(e)}", exc_info=True)
        return ApprovalResult(
            status="failure",
            patient_id=payload.get("patient_id", "UNKNOWN"),
            domain=payload.get("domain", "UNKNOWN"),
            action_taken="error",
            field_updated=None,
            message=f"Error processing approval: {str(e)}",
            timestamp=datetime.utcnow().isoformat()
        )


# ============================================================================
# STANDALONE ENTRY POINT FOR HTTP TRIGGER
# ============================================================================

def handle_approval_webhook(request_body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entry point for Azure Function or HTTP endpoint.
    
    Receives Teams approval callback and processes it.
    
    Args:
        request_body: HTTP request body containing approval payload
        
    Returns:
        JSON response with approval processing status
    """
    try:
        logger.info(f"Received approval webhook: {json.dumps(request_body)}")
        
        result = update_patient_on_approval(request_body)
        
        response = {
            "statusCode": 200 if result.status == "success" else 400,
            "body": result.dict()
        }
        
        logger.info(f"Approval webhook processed: {result.status}")
        return response
    
    except Exception as e:
        logger.error(f"Error handling approval webhook: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "body": {
                "status": "failure",
                "message": f"Error processing webhook: {str(e)}"
            }
        }


# ============================================================================
# TEST/DEMO SECTION
# ============================================================================

if __name__ == "__main__":
    # Example usage (set AZURE_SQL_CONNECTION_STRING environment variable first)
    
    sample_payload = {
        "patient_id": "P003",
        "domain": "medical",
        "correlation_id": "P003_medical",
        "action": "complete",
        "approver_email": "satya.metla@capgemini.com",
        "approver_name": "Satya Metla",
        "approved_timestamp": "2026-04-23T10:35:22Z"
    }
    
    print("=" * 80)
    print("APPROVAL HANDLER - TEST")
    print("=" * 80)
    print(f"\nProcessing approval payload:")
    print(json.dumps(sample_payload, indent=2))
    
    try:
        result = update_patient_on_approval(sample_payload)
        print(f"\nResult:")
        print(json.dumps(result.dict(), indent=2))
    except Exception as e:
        print(f"\nError: {str(e)}")
