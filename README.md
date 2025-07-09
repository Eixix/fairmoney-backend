# 💸 FairMoney

**FairMoney** is a privacy-first, open-source alternative to apps like Tricount. It helps groups track shared expenses
and settle debts fairly — perfect for roommates, trips, events, or any situation involving shared costs.

- 🧮 Group expense management
- 🔐 Secure login & password hashing (Argon2)
- ⚡ Built with Axum + SQLite (backend)
- 🖥️ Cross-platform desktop app via Tauri + React (frontend)
- 🌐 Self-hostable with a minimal footprint

---

## 🚀 Features

- User registration & login (with Argon2 password hashing)
- Create & manage groups
- Add shared bills and track who owes what
- Simple debt simplification logic
- Cross-platform desktop support (Tauri)
- SQLite-powered, no external dependencies needed
- REST API designed for self-hosting

---

## 📦 Tech Stack

| Layer        | Tech                        |
|--------------|-----------------------------|
| **Frontend** | React + Tauri               |
| **Backend**  | Rust + Axum + SQLx + SQLite |
| **Auth**     | JWT (stateless sessions)    |
| **Crypto**   | Argon2 + OsRng              |

---

## 🛠️ Getting Started

```bash
# Clone the repo
git clone https://github.com/yourusername/fairmoney.git
cd fairmoney

# Set up the backend
cd backend

# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Run migrations (if needed)
cargo install sqlx-cli
sqlx migrate run

# Run the API
cargo run
```

## 🔐 API Overview

| Method | Route           | Description           |
|--------|-----------------|-----------------------|
| POST   | `/api/register` | Register a user       |
| POST   | `/api/login`    | Login & get JWT token |
| GET    | `/api/groups`   | Get user's groups     |
| POST   | `/api/groups`   | Create a group        |
| POST   | `/api/bills`    | Add bill to a group   |

    Auth-protected endpoints use Authorization: Bearer <token> header.

## 🔧 Environment

| Variable       | Default            | Description                 |
|----------------|--------------------|-----------------------------|
| `DATABASE_URL` | `sqlite://data.db` | SQLite connection string    |
| `JWT_SECRET`   | `secret`           | Secret key for signing JWTs |

Create a .env file:

```
DATABASE_URL=sqlite://data.db
JWT_SECRET=super-secret-key
```

## 🌍 Why FairMoney?

Unlike existing apps, FairMoney is:
- 💡 Open source
- 🧘 Self-hostable
- 🕵️ Privacy-respecting
- 💻 Cross-platform

Let’s build a fairer way to share money — together.