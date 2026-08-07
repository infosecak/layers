# Use an official Node.js image
FROM node:22-alpine

# Set working directory inside container
WORKDIR /app

# Copy dependency files first
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the project
COPY . .

# Vite default port
EXPOSE 5173

# Allow Vite to be accessed outside the container
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]