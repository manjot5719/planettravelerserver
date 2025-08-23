# Planet Traveler License Server

This is the license server for the Planet Traveler Pro script.

## Setup

1. Clone this repository
2. Run `npm install` to install dependencies
3. Set environment variables:
   - `ADMIN_PASSWORD`: Your secure admin password
4. Run `npm start` to start the server

## API Endpoints

- `GET /` - Server status
- `GET /health` - Health check
- `POST /validate` - Validate a license
- `POST /admin/add-license` - Add a new license
- `GET /admin/licenses` - View all licenses

## Deployment

This server is designed to be deployed on Render.com with automatic deployments from GitHub.