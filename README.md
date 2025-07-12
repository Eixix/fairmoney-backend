# FairMoney API

A complete expense tracking API built with Rust and Actix-web, similar to Tricount or Splitwise. Users can create groups, add members, and track shared expenses with detailed transaction sharing.

## Features

- **User Authentication**: JWT-based authentication with secure password hashing
- **Group Management**: Create groups and manage members
- **Expense Tracking**: Add transactions with detailed sharing among group members
- **Transaction History**: View all transactions in a group with sharing details
- **Authorization**: Proper access control based on group membership

## Tech Stack

- **Framework**: Actix-web
- **Database**: SQLite with SQLx
- **Authentication**: JWT tokens
- **Password Hashing**: Argon2
- **Serialization**: Serde

## Setup

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd fairmoney-backend
   ```

3. **Environment Variables**:
   Create a `.env` file in the root directory:
   ```env
   DATABASE_URL=sqlite:fairmoney.db
   JWT_SECRET=your-super-secret-jwt-key-here
   ```

4. **Database Setup**:
   ```bash
   # Run migrations
   sqlx database create
   sqlx migrate run
   ```

5. **Run the application**:
   ```bash
   cargo run
   ```

The API will be available at `http://127.0.0.1:3000`

## API Endpoints

### Authentication

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

Response:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "uuid-here",
    "username": "john_doe",
    "email": "john@example.com",
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <token>
```

### Groups

#### Create Group
```http
POST /api/groups
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Weekend Trip"
}
```

#### Get User's Groups
```http
GET /api/groups
Authorization: Bearer <token>
```

#### Get Group Details
```http
GET /api/groups/{group_id}
Authorization: Bearer <token>
```

Response includes group info and all members.

#### Add Group Member
```http
POST /api/groups/{group_id}/members
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": "user-uuid-here"
}
```

#### Remove Group Member
```http
DELETE /api/groups/{group_id}/members/{user_id}
Authorization: Bearer <token>
```

### Transactions

#### Create Transaction
```http
POST /api/transactions
Authorization: Bearer <token>
Content-Type: application/json

{
  "group_id": "group-uuid-here",
  "amount": 5000,
  "description": "Dinner at restaurant",
  "shares": [
    {
      "user_id": "user1-uuid",
      "amount": 2500
    },
    {
      "user_id": "user2-uuid",
      "amount": 2500
    }
  ]
}
```

**Note**: Amounts are in cents. Total shares must equal the transaction amount.

#### Get Group Transactions
```http
GET /api/transactions/group/{group_id}
Authorization: Bearer <token>
```

#### Get Transaction Details
```http
GET /api/transactions/{transaction_id}
Authorization: Bearer <token>
```

#### Delete Transaction
```http
DELETE /api/transactions/{transaction_id}
Authorization: Bearer <token>
```

Only the person who paid can delete a transaction.

## Data Models

### User
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "created_at": "datetime"
}
```

### Group
```json
{
  "id": "uuid",
  "name": "string",
  "created_by": "user-id",
  "created_at": "datetime"
}
```

### Transaction
```json
{
  "id": "uuid",
  "group_id": "uuid",
  "paid_by": "user-id",
  "amount": "integer (cents)",
  "description": "string (optional)",
  "created_at": "datetime"
}
```

### TransactionShare
```json
{
  "transaction_id": "uuid",
  "user_id": "uuid",
  "amount": "integer (cents)"
}
```

## Error Handling

The API returns consistent error responses:

```json
{
  "error": "Error Type",
  "message": "Detailed error message"
}
```

Common error types:
- `Unauthorized`: Invalid or missing authentication
- `Forbidden`: Insufficient permissions
- `NotFound`: Resource not found
- `Bad Request`: Invalid request data

## Security Features

- **Password Hashing**: Argon2 for secure password storage
- **JWT Authentication**: Stateless authentication with expiration
- **Authorization**: Group-based access control
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: Parameterized queries with SQLx

## Development

### Running Tests
```bash
cargo test
```

### Database Migrations
```bash
# Create new migration
sqlx migrate add <migration_name>

# Run migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert
```

### Code Formatting
```bash
cargo fmt
```

### Linting
```bash
cargo clippy
```

## Example Usage

Here's a complete example of creating a group and adding an expense:

1. **Register a user**:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"password123"}'
```

2. **Login and get token**:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"password123"}'
```

3. **Create a group**:
```bash
curl -X POST http://localhost:3000/api/groups \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Weekend Trip"}'
```

4. **Add a transaction**:
```bash
curl -X POST http://localhost:3000/api/transactions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "group_id":"<group-id>",
    "amount":5000,
    "description":"Dinner",
    "shares":[
      {"user_id":"<alice-user-id>","amount":5000}
    ]
  }'
```

## License

This project is licensed under the MIT License.