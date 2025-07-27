#!/bin/bash

# CardioMed Clinic Server Setup Script
# This script helps set up the development environment

echo "🏥 CardioMed Clinic Server Setup"
echo "================================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js v18+ and try again."
    exit 1
fi

# Check Node.js version
NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version is too old. Please upgrade to v18+ and try again."
    exit 1
fi

echo "✅ Node.js $(node -v) is installed"

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL is not installed."
    echo "Please install PostgreSQL and try again:"
    echo "  macOS: brew install postgresql"
    echo "  Ubuntu: sudo apt install postgresql postgresql-contrib"
    exit 1
fi

echo "✅ PostgreSQL is installed"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your database credentials"
    echo "⚠️  Generate a JWT secret using: node -e \"console.log(require('crypto').randomBytes(64).toString('hex'))\""
else
    echo "✅ .env file already exists"
fi

# Check if database connection works
echo "🔌 Testing database connection..."
node -e "
import('./config/database.js').then(async (db) => {
  try {
    await db.query('SELECT 1');
    console.log('✅ Database connection successful');
    process.exit(0);
  } catch (error) {
    console.log('❌ Database connection failed:', error.message);
    console.log('💡 Please check your database credentials in .env file');
    console.log('💡 Make sure PostgreSQL is running and database exists');
    process.exit(1);
  }
});
" 2>/dev/null

DB_SUCCESS=$?

if [ $DB_SUCCESS -eq 0 ]; then
    echo "🗄️  Running database migrations..."
    npm run migrate
    
    if [ $? -eq 0 ]; then
        echo "✅ Database migrations completed"
    else
        echo "❌ Database migrations failed"
        exit 1
    fi
else
    echo "⚠️  Skipping migrations due to database connection issues"
fi

echo ""
echo "🎉 Setup completed!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Generate a JWT secret if you haven't already"
echo "3. Start the development server: npm run dev"
echo ""
echo "Useful commands:"
echo "  npm run dev     - Start development server"
echo "  npm start       - Start production server"
echo "  npm run migrate - Run database migrations"
echo ""
echo "API will be available at: http://localhost:5000"
echo "Health check: http://localhost:5000/api/health"
