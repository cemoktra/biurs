pub enum AuthenticateRequest {
    CreateChallenge,
    VerifyChallenge(String),
}

pub enum AuthenticateResponse {
    Challenge(String),
    Token(String),
    Unauthorized,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChallengeClaims {
    pub challenge: String,
    pub exp: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct AuthClaims {
    pub exp: u64,
}

impl TryFrom<crate::proto::biurs_v1::AuthenticateRequest> for AuthenticateRequest {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::AuthenticateRequest) -> Result<Self, Self::Error> {
        match value
            .message
            .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                "AuthenticateRequest",
                "message",
            ))? {
            crate::proto::biurs_v1::authenticate_request::Message::CreateChallenge(_) => {
                Ok(AuthenticateRequest::CreateChallenge)
            }
            crate::proto::biurs_v1::authenticate_request::Message::VerifyChallenge(signature) => {
                Ok(AuthenticateRequest::VerifyChallenge(signature))
            }
        }
    }
}

impl TryFrom<crate::proto::biurs_v1::AuthenticateResponse> for AuthenticateResponse {
    type Error = crate::types::TypeError;

    fn try_from(value: crate::proto::biurs_v1::AuthenticateResponse) -> Result<Self, Self::Error> {
        match value
            .message
            .ok_or(crate::types::TypeError::MandatoryFieldMissing(
                "AuthenticateResponse",
                "message",
            ))? {
            crate::proto::biurs_v1::authenticate_response::Message::Challenge(challenge) => {
                Ok(AuthenticateResponse::Challenge(challenge))
            }
            crate::proto::biurs_v1::authenticate_response::Message::Token(token) => {
                Ok(AuthenticateResponse::Token(token))
            }
            crate::proto::biurs_v1::authenticate_response::Message::Unauthorized(_) => {
                Ok(AuthenticateResponse::Unauthorized)
            }
        }
    }
}

impl From<AuthenticateRequest> for crate::proto::biurs_v1::AuthenticateRequest {
    fn from(value: AuthenticateRequest) -> Self {
        match value {
            AuthenticateRequest::CreateChallenge => crate::proto::biurs_v1::AuthenticateRequest {
                message: Some(
                    crate::proto::biurs_v1::authenticate_request::Message::CreateChallenge(()),
                ),
            },
            AuthenticateRequest::VerifyChallenge(signature) => {
                crate::proto::biurs_v1::AuthenticateRequest {
                    message: Some(
                        crate::proto::biurs_v1::authenticate_request::Message::VerifyChallenge(
                            signature,
                        ),
                    ),
                }
            }
        }
    }
}

impl From<AuthenticateResponse> for crate::proto::biurs_v1::AuthenticateResponse {
    fn from(value: AuthenticateResponse) -> Self {
        match value {
            AuthenticateResponse::Challenge(challenge) => {
                crate::proto::biurs_v1::AuthenticateResponse {
                    message: Some(
                        crate::proto::biurs_v1::authenticate_response::Message::Challenge(
                            challenge,
                        ),
                    ),
                }
            }
            AuthenticateResponse::Token(token) => crate::proto::biurs_v1::AuthenticateResponse {
                message: Some(crate::proto::biurs_v1::authenticate_response::Message::Token(token)),
            },
            AuthenticateResponse::Unauthorized => crate::proto::biurs_v1::AuthenticateResponse {
                message: Some(
                    crate::proto::biurs_v1::authenticate_response::Message::Unauthorized(()),
                ),
            },
        }
    }
}

impl ChallengeClaims {
    pub fn decode(
        token: &str,
        key: &jsonwebtoken::DecodingKey,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        let token_data = jsonwebtoken::decode::<ChallengeClaims>(token, key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn encode(
        &self,
        key: &jsonwebtoken::EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        jsonwebtoken::encode(&header, self, key)
    }
}
