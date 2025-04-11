# Authentication Service V2

A robust authentication service built with Node.js, Express, TypeScript, and MongoDB. This service provides secure user authentication and authorization functionality.

## Features

- User registration and login
- Password hashing using bcrypt
- JWT-based authentication
- MongoDB database integration
- TypeScript for type safety
- Docker support for containerization
- Comprehensive test suite with Jest

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

```
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
PORT=3000
```

## Development

To start the development server:

```bash
npm run dev
```

The server will start with hot-reloading enabled.

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
src/           # Source code
tests/         # Test files
├── src/       # Main application code
├── tests/     # Test files
├── .env       # Environment variables
├── Dockerfile # Docker configuration
└── docker-compose.yml # Docker Compose configuration
```

## Dependencies

### Main Dependencies

- Express.js - Web framework
- Mongoose - MongoDB ODM
- bcrypt - Password hashing
- jsonwebtoken - JWT implementation
- cors - Cross-origin resource sharing
- dotenv - Environment variable management

### Development Dependencies

- TypeScript
- Jest - Testing framework
- ts-jest - TypeScript testing support
- ts-node-dev - Development server
- MongoDB Memory Server - In-memory MongoDB for testing

## License

ISC

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request
