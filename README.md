# OAUTH Upfirst

## Endpoints

- **GET**: /api/oauth/authorize - Generate JWT token using client_id and redirect_url. Takes parameters `response_type, client_id, redirect_uri, state` and redirects user if successful.
- **POST**: /api/oauth/token - Validates code token and generates access and refresh tokens. Takes parameters `grant_type, code, client_id, redirect_uri, refresh_token` and returns `access_token, refresh_token, token_type, expires_in`.

## Installation

```bash
# Clone the repository
git clone https://github.com/spaaacy/oauth-upfirst.git
cd oauth-upfirst

# Install dependencies
npm install
# or
yarn install
```

## Usage

```bash
# Start the project
npm run start

# Start the application in development mode
npm run serve
```

## Ensure you have the following installed before running the project:

- Node.js (Latest LTS recommended)
- npm (Comes with Node.js) or yarn
