# Authentication Service V2

A robust and secure authentication service built with Node.js, Express, TypeScript, and MongoDB. This service provides comprehensive user authentication and authorization functionality with enhanced security features.

## Features

- User registration and login with email verification
- Password hashing using bcrypt
- JWT-based authentication with refresh tokens
- MongoDB database integration with Mongoose
- TypeScript for type safety and better development experience
- Docker support for containerization
- Comprehensive test suite with Jest
- Rate limiting for API endpoints
- Security headers with Helmet
- Input validation with express-validator
- Cookie-based session management
- Password reset functionality
- Security audit capabilities

## Prerequisites

- Node.js (v14 or higher)
- MongoDB
- Docker (optional)
- npm or yarn

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd auth-service-v2
```

2. Install dependencies:

```bash
npm install
```

3. Create a `.env` file in the root directory with the following variables:

```env
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_token_secret
PORT=3000
NODE_ENV=development
```

## Development

To start the development server with hot-reloading:

```bash
npm run dev
```

## Building

To build the TypeScript project:

```bash
npm run build
```

## Testing

Run the test suite:

```bash
npm test
```

## Security Audit

Run security checks:

```bash
npm run audit
```

## Docker Support

The project includes Docker support for containerization:

1. Build the Docker image:

```bash
docker build -t auth-service .
```

2. Run using Docker Compose:

```bash
docker-compose up
```

## Project Structure

```
src/
├── config/         # Configuration files
├── controllers/    # Route controllers
├── middleware/     # Custom middleware
├── models/         # Database models
├── routes/         # API routes
├── types/          # TypeScript type definitions
├── app.ts          # Express application setup
└── index.ts        # Application entry point
```

## Dependencies

### Main Dependencies

- Express.js - Web framework
- Mongoose - MongoDB ODM
- bcrypt - Password hashing
- jsonwebtoken - JWT implementation
- cors - Cross-origin resource sharing
- dotenv - Environment variable management
- helmet - Security headers
- express-rate-limit - Rate limiting
- express-validator - Input validation
- cookie-parser - Cookie management

### Development Dependencies

- TypeScript
- Jest - Testing framework
- ts-jest - TypeScript testing support
- ts-node-dev - Development server
- MongoDB Memory Server - In-memory MongoDB for testing
- Supertest - HTTP testing
- Various TypeScript type definitions

## API Endpoints

- POST /api/auth/register - User registration
- POST /api/auth/login - User login
- POST /api/auth/refresh - Refresh access token
- POST /api/auth/logout - User logout
- POST /api/auth/forgot-password - Request password reset
- POST /api/auth/reset-password - Reset password
- GET /api/auth/verify-email - Email verification

## Security Features

- Rate limiting on all endpoints
- Helmet security headers
- Input validation and sanitization
- Secure password hashing
- JWT token rotation
- Cookie security
- CORS protection
- Environment variable protection

## License

ISC

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request
