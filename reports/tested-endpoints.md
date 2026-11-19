# KNOT Security Assessment – Tested Endpoints

This document catalogs the application endpoints reviewed, tested, and analyzed during the authorized security audit of **KNOT** (`https://knotnow.co` and `https://sapi.knotnow.co`).

---

## Summary of Endpoint Testing

| # | Endpoint | Method | Component | Auth Required | Edge / WAF Status | Authorization Model | Potential Risk / Verification Status |
|---|---|---|---|---|---|---|---|
| 1 | `/` | GET | Global Config / CDN | No | 200 OK | Public configuration | Informational: returns app feature flags |
| 2 | `/*` | OPTIONS | CORS Middleware | No | 200 OK | Dynamic reflection of Origin | **Confirmed Finding (High)**: Reflects arbitrary origins with credentials |
| 3 | `/orders/active` | GET | Order Management | Yes | 429 Blocked (unauth) | Bound to session token | Low risk: List endpoint scoped to authenticated session |
| 4 | `/orders/all` | GET | Order History | Yes | 429 Blocked (unauth) | Bound to session token | Low risk: List endpoint scoped to authenticated session |
| 5 | `/orders/order/{id}` | GET | Order Details | Yes | 429 Blocked (unauth) | Object-level ID in path (`{id}`) | **Potential Risk (High)**: IDOR/BOLA if backend lacks user-ownership check; unverified (requires 2 test accounts) |
| 6 | `/orders/order_updt` | POST | Order Slot / Cancel | Yes | 429 Blocked (unauth) | Body parameter `order_id` | **Potential Risk (High)**: IDOR/BOLA if backend does not verify order ownership; unverified |
| 7 | `/cancel_order` | POST | Order Cancellation | Yes | 429 Blocked (unauth) | SDUI action call | **Potential Risk (Medium)**: Order cancellation without secondary validation; unverified |
| 8 | `/user/profile/` | GET | User Profile | Yes | 429 Blocked (unauth) | Bound to session token | Low risk: Scoped to authenticated session |
| 9 | `/user_address/loc_page_data` | GET | Saved Addresses | Yes | 429 Blocked (unauth) | Query parameter `?address_id={id}` | **Potential Risk (High)**: IDOR/BOLA if `address_id` is enumerable and lacks user isolation; unverified |
| 10 | `/user_address/` | POST | Address Mutation | Yes | 429 Blocked (unauth) | Body payload `address_data` | Medium risk: Address update authorization |
| 11 | `/user/manage_acc` | GET | Account Management | Yes | 429 Blocked (unauth) | Bound to session token | Scoped to authenticated session |
| 12 | `/user/logout` | GET | Session Termination | Yes | 429 Blocked (unauth) | Session token invalidation | **Potential Risk (Medium)**: Client-side deletion vs server-side revocation |
| 13 | `/gift-cards/wallet` | GET | Wallet & Gift Card | Yes | 429 Blocked (unauth) | Bound to session token | Scoped to authenticated session; balances server-calculated |
| 14 | `/gift-cards/txn/start` | POST | Wallet Recharge Start | Yes | 429 Blocked (unauth) | Server-generated Razorpay order | Medium risk: Amount tampering prevented if validated server-side |
| 15 | `/gift-cards/txn/verify` | POST | Wallet Recharge Verify| Yes | 429 Blocked (unauth) | Body parameter `order_id` | **Critical Architecture Check**: Must verify signature or query Razorpay API server-to-server |
| 16 | `/upload_handler/profile` | POST | Media Upload | Yes | 429 Blocked (unauth) | Multipart file upload | **Potential Risk (Medium)**: File type validation / MIME spoofing / stored content risk |

---

## Detailed Endpoint Breakdown

### 1. Root Configuration (`GET /`)
- **URL**: `https://sapi.knotnow.co/`
- **Method**: `GET`
- **Authentication**: None
- **Observed Response**: HTTP 200 OK
- **Headers**:
  ```http
  HTTP/2 200
  content-type: application/json
  server_timestamp: 2026-11-19T07:28:45.579752
  access-control-allow-origin: *
  access-control-allow-credentials: true
  access-control-expose-headers: *
  cache-control: public, max-age=1
  ```
- **Body**:
  ```json
  {
    "for": "fashion",
    "component_data": [
      {
        "bloc_id": "global_app_data",
        "amplitude_compact_properties_enabled": true,
        "amplitude_noise_filter_enabled": true,
        "tryon_collection_disabled": true,
        "tryon_v3_enabled": false,
        "facebook_events": ["view_item", "add_to_wishlist", "login", "INITIATE_PURCHASE"],
        "blocked_branch_events": ["view_items"],
        "gift_card_coupons_enabled": false
      }
    ]
  }
  ```
- **Security Assessment**: Public configuration endpoint. Contains no sensitive customer PII. However, the headers exhibit an insecure CORS policy (`access-control-allow-origin: *` alongside `access-control-allow-credentials: true`).

---

### 2. CORS Preflight (`OPTIONS /*`)
- **URL**: `https://sapi.knotnow.co/` and all subpaths (`/user/profile/`, `/orders/all`, etc.)
- **Method**: `OPTIONS`
- **Headers Sent**:
  ```http
  Origin: https://evil.com
  Access-Control-Request-Method: POST
  Access-Control-Request-Headers: authorization, content-type
  ```
- **Observed Response**:
  ```http
  HTTP/2 200
  vary: Origin
  access-control-allow-origin: https://evil.com
  access-control-allow-credentials: true
  access-control-allow-headers: authorization, content-type
  access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT
  access-control-max-age: 600
  ```
- **Security Assessment**: **CONFIRMED VULNERABILITY (HIGH)**. The server dynamically reflects any incoming `Origin` value and pairs it with `Access-Control-Allow-Credentials: true`. Any external website can perform authenticated API interactions on behalf of a user if credentials or ambient cookies are transmitted.

---

### 3. Active Orders (`GET /orders/active`)
- **URL**: `https://sapi.knotnow.co/orders/active`
- **Method**: `GET`
- **Authentication**: Required (`Authorization: Bearer <accessToken>`)
- **Edge/WAF Behavior**: Direct unauthenticated requests from curl/python without browser session state receive `HTTP/2 429` ("The request is blocked.") from Azure Front Door WAF.
- **Client Implementation**: Triggered on homepage load by the order carousel (`OrderCarousel: Making immediate API call to /orders/active`).
- **Authorization Model**: Scoped to the authenticated user's session token.

---

### 4. All Past Orders (`GET /orders/all`)
- **URL**: `https://sapi.knotnow.co/orders/all`
- **Method**: `GET`
- **Authentication**: Required (`Authorization: Bearer <accessToken>`)
- **Edge/WAF Behavior**: HTTP/2 429 (Blocked) without active session.
- **Client Implementation**: Dispatched via `$.eR().nK(0, "/orders/all", t.z)`.
- **Authorization Model**: List endpoint; query results are bound to the authenticated user ID extracted from the token.

---

### 5. Order Details by ID (`GET /orders/order/{id}`)
- **URL**: `https://sapi.knotnow.co/orders/order/{id}`
- **Method**: `GET`
- **Authentication**: Required
- **Client Implementation**:
  ```javascript
  new A.bp(B.R, null, null, null, A.a(["params_type","background","hide_snack_bar",!0,"endpoint","/orders/order/"+a,"request_type","get"], t.N, t.z))
  ```
- **Authorization Model**: The order ID is passed directly in the URL route (`/orders/order/{id}`).
- **Security Concern**: **BOLA / IDOR Potential**. If the server executes `SELECT * FROM orders WHERE id = :id` without verifying that `orders.user_id == current_user_id`, an attacker can access order history, recipient names, addresses, and order items by guessing or enumerating IDs.
- **Status**: UNVERIFIED (Production safety rules prohibit guessing other customers' order IDs; requires a secondary authorized test account).

---

### 6. Order Update / Rescheduling (`POST /orders/order_updt`)
- **URL**: `https://sapi.knotnow.co/orders/order_updt`
- **Method**: `POST`
- **Authentication**: Required
- **Payload Structure**:
  ```json
  {
    "order_id": "<target_order_id>",
    "cancel": false,
    "slot_picked": ["<delivery_slot_start>", "<delivery_slot_end>"]
  }
  ```
- **Security Concern**: **BOLA / IDOR on State Change**. If the server does not enforce resource ownership verification before applying updates or cancellations, User A could alter delivery slots or cancel User B's pending order by supplying User B's `order_id`.
- **Status**: UNVERIFIED (Requires 2 accounts).

---

### 7. Cancel Order (`POST /cancel_order`)
- **URL**: `https://sapi.knotnow.co/cancel_order`
- **Method**: `POST`
- **Authentication**: Required
- **Client Implementation**: Dispatched via Server-Driven UI action upon clicking confirmation dialog.
- **Security Concern**: Must enforce that only the buyer or an admin can cancel an order, and only when the order status permits cancellation (e.g. before dispatch).

---

### 8. User Profile (`GET /user/profile/`)
- **URL**: `https://sapi.knotnow.co/user/profile/`
- **Method**: `GET`
- **Authentication**: Required (`Authorization: Bearer <accessToken>`)
- **Authorization Model**: Queries profile details corresponding to `user_id` inside JWT.

---

### 9. Address Location Page Data (`GET /user_address/loc_page_data`)
- **URL**: `https://sapi.knotnow.co/user_address/loc_page_data?address_id={id}`
- **Method**: `GET`
- **Authentication**: Required
- **Client Implementation**:
  ```javascript
  if (a != null) J.a6(n, "address_id", a);
  return A.k(i.mD(0, "/user_address/loc_page_data", n, h));
  ```
- **Security Concern**: **BOLA / IDOR on Customer Address Data**. The `address_id` is supplied as a request parameter. If backend database filtering does not include `AND user_id = :authenticated_user_id`, customer physical addresses, geolocation coordinates, floor/flat numbers, and recipient phone numbers are vulnerable to unauthorized extraction.
- **Status**: UNVERIFIED (Requires 2 accounts).

---

### 10. Address Creation & Update (`POST /user_address/`)
- **URL**: `https://sapi.knotnow.co/user_address/`
- **Method**: `POST`
- **Authentication**: Required
- **Payload Structure**:
  ```json
  {
    "updt_loc_call": false,
    "address_data": [
      {
        "residence_number": "...",
        "location": {
          "pincode": "..."
        }
      }
    ]
  }
  ```
- **Security Concern**: Address updates must verify that the `address_id` being updated belongs to the authenticated user.

---

### 11. Gift Card & Wallet Balance (`GET /gift-cards/wallet`)
- **URL**: `https://sapi.knotnow.co/gift-cards/wallet`
- **Method**: `GET`
- **Parameters**: `?filter=...&qp=...`
- **Authentication**: Required
- **Security Assessment**: Wallet ledger retrieval. Balances are computed server-side from ledger entries. The client cannot overwrite the balance directly through this endpoint.

---

### 12. Gift Card / Wallet Transaction Initiation (`POST /gift-cards/txn/start`)
- **URL**: `https://sapi.knotnow.co/gift-cards/txn/start`
- **Method**: `POST`
- **Headers**: `X-Idempotency-Key: <UUID>`
- **Authentication**: Required
- **Security Assessment**: Creates a Razorpay payment order. Uses `X-Idempotency-Key` to prevent duplicate transaction initialization on client retries.

---

### 13. Gift Card / Wallet Transaction Verification (`POST /gift-cards/txn/verify`)
- **URL**: `https://sapi.knotnow.co/gift-cards/txn/verify`
- **Method**: `POST`
- **Payload**:
  ```json
  {
    "order_id": "<razorpay_or_internal_order_id>"
  }
  ```
- **Security Concern**: **Financial Crediting Integrity**. The client submits only `order_id` to verify payment.
  - **Critical Rule**: The backend must independently query Razorpay (`GET /v1/orders/{order_id}`) and confirm `status == 'paid'` AND verify that the order amount matches the planned credit amount before crediting the wallet.
  - If the backend credits funds without server-to-server confirmation, an attacker could attempt to submit uncompleted order IDs.
- **Status**: Code review completed; server-side verification requires sandbox retesting.
