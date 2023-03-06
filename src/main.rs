use anyhow;
use chrono::{Duration, Utc};
use jwt_compact::{
    alg::{Hs256, Hs256Key},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use warp::reject::Reject;
use warp::{Filter, Rejection, Reply};

#[derive(Debug)]
enum ApiError {
    TabshiUnauthorized,
    NotFound,
    InternalServerError,
    TabUserinfoerror,
}
impl Reject for ApiError {}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    code: u16,
    msg: String,
    data: T,
}

/// 生成 jwt token
async fn generate_jwt_token() -> Result<String, ApiError> {
    let time_options = TimeOptions::default();

    // 创建一个对称HMAC密钥，它将用于创建和验证令牌
    let key = Hs256Key::new(b"super_secret_key_donut_steel");

    // Create a token.
    let header = Header::default().with_key_id("my-key");

    let claims = Claims::new(CustomClaims {
        username: "admin".to_owned(),
        roles: vec!["Admin".to_owned()],
        permissions: vec![
            "read:system".to_owned(),
            "write:system".to_owned(),
            "delete:system".to_owned(),
        ],
        // exp: 1615466982,
        avatar: "https://i.gtimg.cn/club/item/face/img/2/16022_100.gif".to_owned(),
    })
    .set_duration_and_issuance(&time_options, Duration::days(7))
    .set_not_before(Utc::now() - Duration::hours(1));

    let token_string = Hs256.token(header, &claims, &key).unwrap();
    println!("token: {}", token_string);
    Ok(token_string)
}

/// 验证token
async fn validate_jwt_token(token_string: String) -> Result<CustomClaims, ApiError> {
    let key = Hs256Key::new(b"super_secret_key_donut_steel");
    let time_options = TimeOptions::default();
    // 解析token
    let token = UntrustedToken::new(&token_string).unwrap();
    // Before verifying the token, we might find the key which has signed the token
    // using the `Header.key_id` field.
    assert_eq!(token.header().key_id, Some("my-key".to_owned()));
    // Validate the token integrity.
    let token: Token<CustomClaims> = Hs256.validate_integrity(&token, &key).unwrap();

    let time = token.claims().issued_at.unwrap();
    let time_options = TimeOptions::new(Duration::seconds(60), move || time);
    // Validate additional conditions.
    token
        .claims()
        .validate_expiration(&time_options)
        .unwrap()
        .validate_maturity(&time_options)
        .unwrap();
    // Now, we can extract information from the token (e.g., its subject).
    let custom_claims = &token.claims().custom;
    Ok(custom_claims.clone())
}

// JWT令牌结构体
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
struct CustomClaims {
    username: String,
    roles: Vec<String>,
    permissions: Vec<String>,
    // exp: usize,
    avatar: String,
}

async fn login_handler(login_request: LoginRequest) -> Result<impl Reply, Rejection> {
    // 检查用户名和密码是否正确，如果正确，生成一个JWT令牌并返回给客户端
    let token = generate_jwt_token().await?;
    let login_response = LoginResponse {
        token: token.to_owned(),
    };
    let api_response = ApiResponse {
        code: 200,
        msg: "success".to_owned(),
        data: login_response,
    };
    Ok(warp::reply::json(&api_response))
}

#[derive(Serialize)]
struct UserInfoResponse {
    username: String,
    roles: Vec<String>,
    permissions: Vec<String>,
    avatar: String,
}

async fn userinfo_handler(token: String) -> Result<impl Reply, Rejection> {
    // 解析JWT令牌
    let token_parts: Vec<&str> = token.split(' ').collect();
    if token_parts.len() != 2 || token_parts[0] != "Bearer" {
        return Err(warp::reject::custom(ApiError::TabUserinfoerror));
    }
    let token = token_parts[1];
    print!("userinfo{}", token);
    let token_data = match validate_jwt_token(token.to_owned()).await {
        Ok(token_data) => token_data,
        Err(_) => return Err(warp::reject::custom(ApiError::TabUserinfoerror)),
    };

    // 构建用户信息并返回
    let userinfo = UserInfoResponse {
        username: token_data.username,
        roles: token_data.roles,
        permissions: token_data.permissions,
        avatar: "https://i.gtimg.cn/club/item/face/img/2/16022_100.gif".to_owned(),
    };
    let api_response = ApiResponse {
        code: 200,
        msg: "success".to_owned(),
        data: userinfo,
    };
    Ok(warp::reply::json(&api_response))
}

fn with_auth() -> impl Filter<Extract = (String,), Error = warp::reject::Rejection> + Clone {
    warp::header::headers_cloned().and_then(|headers: warp::http::HeaderMap| async move {
        let auth_header = headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_owned());

        match auth_header {
            Some(token) => {
                // print!("auth-----: {}", token);
                Ok(token)
            }
            None => {
                // print!("aerror----: {}", "error");
                Err(warp::reject::custom(ApiError::TabshiUnauthorized))
            }
        }
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // 构建登录接口过滤器
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allow_headers(vec![
            "Content-Type",
            "Authorization",
            "Accept",
            "Accept-Encoding",
            "Accept-Language",
        ]);

    let login_api = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(login_handler);

    let userinfo_api = warp::path("userInfo")
        .and(warp::get())
        .and(with_auth())
        .and_then(userinfo_handler);

    // 组合所有接口过滤器
    let routes = login_api.or(userinfo_api).with(cors);
    // let routes = login_api.with(cors);

    // 启动HTTP服务器
    warp::serve(routes).run(([127, 0, 0, 1], 8080)).await;
}
