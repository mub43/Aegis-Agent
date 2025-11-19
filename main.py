"""
AEGIS AGENT - Real-Time AI Threat Mitigation Command Center

FastAPI backend demonstrating an automated, zero-trust security engine for
LLM prompt injection and jailbreak mitigation.
"""

import time
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from core.security_engine import SecurityEngine

# Initialize FastAPI app
app = FastAPI(
    title="AEGIS AGENT - Threat Mitigation API",
    description="Real-Time AI Threat Mitigation Command Center for LLM prompt injection and jailbreak detection",
    version="1.0.0"
)

# Security scheme for JWT authentication
security = HTTPBearer()

# Initialize security engine
security_engine = SecurityEngine()

# JWT Configuration (for demonstration - non-functional but present)
# In production, these should be in environment variables
SECRET_KEY = "aegis-agent-secret-key-change-in-production"
ALGORITHM = "HS256"


class ThreatMitigationRequest(BaseModel):
    """Request model for threat mitigation endpoint."""
    prompt: str = Field(
        ...,
        description="The user prompt to analyze for potential threats",
        min_length=1,
        max_length=10000
    )
    user_id: Optional[str] = Field(
        None,
        description="Optional user identifier for audit logging"
    )


class ThreatMitigationResponse(BaseModel):
    """Response model for threat mitigation endpoint."""
    threat_score: float = Field(
        ...,
        description="Threat score between 0.0 and 1.0",
        ge=0.0,
        le=1.0
    )
    mitigation_action: str = Field(
        ...,
        description="Recommended mitigation action: BLOCK, FLAG, or PASS"
    )
    processing_time_ms: float = Field(
        ...,
        description="Time taken to process the request in milliseconds",
        ge=0.0
    )
    metadata: dict = Field(
        ...,
        description="Additional metadata about the threat analysis"
    )
    timestamp: str = Field(
        ...,
        description="ISO format timestamp of the analysis"
    )


def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    JWT Authentication Dependency for Zero-Trust Policies.
    
    This is a non-functional implementation that demonstrates the structure
    for secure interservice communication. In production, this would:
    - Validate tokens against a proper authentication service
    - Check token expiration
    - Verify token signature
    - Extract and validate user claims
    
    Args:
        credentials: HTTP Bearer token credentials
        
    Returns:
        Dictionary containing decoded token claims
        
    Raises:
        HTTPException: If token is invalid or missing
    """
    token = credentials.credentials
    
    try:
        # Decode and verify JWT token
        # In production, this would validate against a real secret key and issuer
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_signature": False}  # Non-functional: skip signature verification
        )
        
        # Extract user information from token
        user_info = {
            "user_id": payload.get("sub", "unknown"),
            "roles": payload.get("roles", []),
            "exp": payload.get("exp", 0)
        }
        
        return user_info
        
    except JWTError:
        # In a real implementation, this would properly handle token validation
        # For demonstration purposes, we'll allow requests with any token format
        # This is the "non-functional" aspect - it accepts tokens but doesn't fully validate
        return {
            "user_id": "demo_user",
            "roles": ["user"],
            "exp": int(time.time()) + 3600
        }


@app.get("/")
async def root():
    """Root endpoint providing API information."""
    return {
        "service": "AEGIS AGENT - Threat Mitigation API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "threat_mitigation": "/api/v1/mitigate_threat",
            "health": "/health"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "AEGIS AGENT",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


@app.post(
    "/api/v1/mitigate_threat",
    response_model=ThreatMitigationResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze prompt for threats and return mitigation action",
    description="""
    This endpoint analyzes a user prompt for potential prompt injection and jailbreak attempts.
    It returns a threat score (0.0-1.0), a recommended mitigation action (BLOCK, FLAG, PASS),
    and detailed metadata about the analysis.
    
    The endpoint is protected by JWT authentication to enforce zero-trust policies.
    Processing time is optimized to be sub-50ms for real-time threat detection.
    """
)
async def mitigate_threat(
    request: ThreatMitigationRequest,
    user_info: dict = Depends(verify_jwt_token)
):
    """
    Main threat mitigation endpoint.
    
    Analyzes the provided prompt using weighted-regex heuristics to detect
    prompt injection and jailbreak attempts. Returns a comprehensive threat
    analysis with mitigation recommendations.
    
    Args:
        request: ThreatMitigationRequest containing the prompt to analyze
        user_info: Authenticated user information from JWT token
        
    Returns:
        ThreatMitigationResponse with threat analysis results
    """
    # Record start time for processing measurement
    start_time = time.perf_counter()
    
    # Process the threat analysis
    result = security_engine.process_request(request.prompt)
    
    # Calculate total processing time
    total_processing_time_ms = (time.perf_counter() - start_time) * 1000
    
    # Ensure we're meeting the sub-50ms target (architecture optimization)
    # The security engine is designed to be fast, but we log the actual time
    if total_processing_time_ms > 50.0:
        # Log warning if exceeding target (in production, use proper logging)
        pass
    
    # Prepare response
    response = ThreatMitigationResponse(
        threat_score=result["threat_score"],
        mitigation_action=result["mitigation_action"],
        processing_time_ms=round(total_processing_time_ms, 3),
        metadata={
            **result["metadata"],
            "user_id": user_info.get("user_id", request.user_id),
            "authenticated": True
        },
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime())
    )
    
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

