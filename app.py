import os
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel

load_dotenv()

app = FastAPI(title="Gmail Agent Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "")
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/"
AUTH0_ALGORITHMS = ["RS256"]

AUTH0_CUSTOM_API_CLIENT_ID = os.getenv("AUTH0_CUSTOM_API_CLIENT_ID", "")
AUTH0_CUSTOM_API_CLIENT_SECRET = os.getenv("AUTH0_CUSTOM_API_CLIENT_SECRET", "")
AUTH0_GOOGLE_CONNECTION = os.getenv("AUTH0_GOOGLE_CONNECTION", "google-oauth2")

GOOGLE_GMAIL_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]

_jwks_cache: Optional[Dict[str, Any]] = None


class UserProfile(BaseModel):
    sub: str
    email: Optional[str] = None
    scope: Optional[str] = None
    permissions: Optional[List[str]] = None


class EmailItem(BaseModel):
    id: str
    threadId: str
    snippet: Optional[str] = None
    subject: Optional[str] = None
    from_: Optional[str] = None


class InboxResponse(BaseModel):
    messages: List[EmailItem]


class SummaryRequest(BaseModel):
    prompt: Optional[str] = None
    max_results: int = 5


class GmailProfile(BaseModel):
    emailAddress: str
    messagesTotal: Optional[int] = None
    threadsTotal: Optional[int] = None
    historyId: Optional[str] = None


def get_jwks() -> Dict[str, Any]:
    global _jwks_cache
    if _jwks_cache is None:
        url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        _jwks_cache = response.json()
    return _jwks_cache


def safe_json(response: requests.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return response.text


def get_current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    print("AUTH HEADER RECEIVED:", "present" if authorization else "missing")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    print("AUTH TOKEN PREFIX:", token[:25] + "..." if token else "empty")

    try:
        unverified_header = jwt.get_unverified_header(token)
        print("UNVERIFIED JWT HEADER:", unverified_header)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token header") from exc

    jwks = get_jwks()
    rsa_key = None
    for key in jwks.get("keys", []):
        if key.get("kid") == unverified_header.get("kid"):
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
            break

    if not rsa_key:
        raise HTTPException(status_code=401, detail="Unable to find matching JWKS key")

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=AUTH0_ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=AUTH0_ISSUER,
        )
        print("JWT PAYLOAD SUB:", payload.get("sub"))
        print("JWT PAYLOAD AUD:", payload.get("aud"))
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(exc)}") from exc

    payload["raw_token"] = token
    return payload


def get_google_access_token_from_token_vault(auth0_user_access_token: str) -> str:
    if not AUTH0_CUSTOM_API_CLIENT_ID or not AUTH0_CUSTOM_API_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Missing AUTH0_CUSTOM_API_CLIENT_ID or AUTH0_CUSTOM_API_CLIENT_SECRET",
        )

    token_url = f"https://{AUTH0_DOMAIN}/oauth/token"

    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AUTH0_CUSTOM_API_CLIENT_ID,
        "client_secret": AUTH0_CUSTOM_API_CLIENT_SECRET,
        "subject_token": auth0_user_access_token,
        "connection": AUTH0_GOOGLE_CONNECTION,
        "scope": " ".join(GOOGLE_GMAIL_SCOPES),
    }

    safe_payload = {
        **payload,
        "client_secret": "***redacted***",
        "subject_token": (
            auth0_user_access_token[:25] + "..."
            if auth0_user_access_token
            else None
        ),
    }

    print("=== TOKEN VAULT DEBUG START ===")
    print("TOKEN URL:", token_url)
    print("AUTH0 DOMAIN:", AUTH0_DOMAIN)
    print("AUTH0 AUDIENCE:", AUTH0_AUDIENCE)
    print("AUTH0 GOOGLE CONNECTION:", AUTH0_GOOGLE_CONNECTION)
    print("CUSTOM API CLIENT ID:", AUTH0_CUSTOM_API_CLIENT_ID)
    print("REQUEST PAYLOAD:", safe_payload)

    response = requests.post(token_url, json=payload, timeout=20)

    print("TOKEN EXCHANGE STATUS:", response.status_code)
    print("TOKEN EXCHANGE BODY:", safe_json(response))
    print("=== TOKEN VAULT DEBUG END ===")

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Token Vault token exchange failed",
                "auth0_status": response.status_code,
                "auth0_response": safe_json(response),
            },
        )

    data = response.json()
    access_token = data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "No Google access token returned",
                "auth0_response": data,
            },
        )

    return access_token


def normalize_headers(headers: List[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for header in headers:
        name = (header.get("name") or "").strip().lower()
        value = (header.get("value") or "").strip()
        if name:
            out[name] = value
    return out


def get_gmail_profile(gmail_access_token: str) -> Dict[str, Any]:
    url = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
    headers = {"Authorization": f"Bearer {gmail_access_token}"}

    response = requests.get(url, headers=headers, timeout=20)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Failed to fetch Gmail profile",
                "gmail_status": response.status_code,
                "gmail_response": safe_json(response),
            },
        )

    return response.json()


def get_message_detail(gmail_access_token: str, message_id: str) -> Dict[str, Any]:
    url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}"
    headers = {"Authorization": f"Bearer {gmail_access_token}"}
    params = {"format": "metadata", "metadataHeaders": ["From", "Subject"]}

    response = requests.get(url, headers=headers, params=params, timeout=20)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": f"Failed to fetch Gmail message {message_id}",
                "gmail_status": response.status_code,
                "gmail_response": safe_json(response),
            },
        )

    return response.json()


def list_recent_messages(gmail_access_token: str, max_results: int = 5) -> List[EmailItem]:
    list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    headers = {"Authorization": f"Bearer {gmail_access_token}"}
    params = {"maxResults": max_results}

    response = requests.get(list_url, headers=headers, params=params, timeout=20)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Failed to fetch Gmail messages",
                "gmail_status": response.status_code,
                "gmail_response": safe_json(response),
            },
        )

    data = response.json()
    raw_messages = data.get("messages", [])
    output: List[EmailItem] = []

    for item in raw_messages:
        message_id = item["id"]
        detail = get_message_detail(gmail_access_token, message_id)
        headers_map = normalize_headers(detail.get("payload", {}).get("headers", []))
        output.append(
            EmailItem(
                id=detail.get("id"),
                threadId=detail.get("threadId"),
                snippet=detail.get("snippet"),
                subject=headers_map.get("subject"),
                from_=headers_map.get("from"),
            )
        )

    return output


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me", response_model=UserProfile)
def me(user: Dict[str, Any] = Depends(get_current_user)) -> UserProfile:
    return UserProfile(
        sub=user.get("sub"),
        email=user.get("email"),
        scope=user.get("scope"),
        permissions=user.get("permissions"),
    )


@app.get("/api/gmail/profile", response_model=GmailProfile)
def gmail_profile(user: Dict[str, Any] = Depends(get_current_user)) -> GmailProfile:
    auth0_access_token = user["raw_token"]
    gmail_access_token = get_google_access_token_from_token_vault(auth0_access_token)
    profile = get_gmail_profile(gmail_access_token)

    return GmailProfile(
        emailAddress=profile.get("emailAddress", ""),
        messagesTotal=profile.get("messagesTotal"),
        threadsTotal=profile.get("threadsTotal"),
        historyId=profile.get("historyId"),
    )


@app.get("/api/gmail/recent", response_model=InboxResponse)
def gmail_recent(
    max_results: int = 5,
    user: Dict[str, Any] = Depends(get_current_user),
) -> InboxResponse:
    if max_results < 1 or max_results > 20:
        raise HTTPException(status_code=400, detail="max_results must be between 1 and 20")

    auth0_access_token = user["raw_token"]
    gmail_access_token = get_google_access_token_from_token_vault(auth0_access_token)
    messages = list_recent_messages(gmail_access_token, max_results=max_results)
    return InboxResponse(messages=messages)


@app.post("/api/gmail/summarize")
def gmail_summarize(
    payload: SummaryRequest,
    user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    auth0_access_token = user["raw_token"]
    gmail_access_token = get_google_access_token_from_token_vault(auth0_access_token)
    messages = list_recent_messages(gmail_access_token, max_results=payload.max_results)

    compact = [
        {
            "from": m.from_,
            "subject": m.subject,
            "snippet": m.snippet,
        }
        for m in messages
    ]

    return {
        "summary": "Phase 1 stub: Auth0 + Token Vault + Gmail access is working. Plug Ollama here next.",
        "emails": compact,
        "prompt_received": payload.prompt,
    }