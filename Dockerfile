# Use an official Node.js runtime
FROM node:18

# Set the working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the source code
COPY . .

# Build the project (if needed)
RUN npm run build

# Expose the desired port
EXPOSE 4000

# Start the compiled app
CMD ["node", "dist/index.js"]
