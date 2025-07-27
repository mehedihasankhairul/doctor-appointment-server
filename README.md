# CardioMed Clinic - Backend Server

A robust Node.js/Express backend server with PostgreSQL database for the CardioMed Clinic application.

## 🚀 Features

- **RESTful API** with Express.js
- **PostgreSQL Database** with connection pooling
- **JWT Authentication** with role-based access control
- **Input Validation** using Joi
- **Security Features** (CORS, Helmet, Rate limiting)
- **File Upload** support for medical documents
- **Comprehensive Logging** with Morgan
- **Database Migrations** and seeding
- **Error Handling** and validation

## 📋 Prerequisites

Before running the server, make sure you have:

- **Node.js** (v18+ recommended)
- **npm** or **yarn**
- **PostgreSQL** (v12+)
- **Git**

## 🛠️ Installation

### 1. Navigate to Server Directory
```bash
cd server
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Database Setup

#### Install PostgreSQL (if not already installed)

**macOS (using Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**Windows:**
Download and install from [PostgreSQL official website](https://www.postgresql.org/download/windows/)

#### Create Database and User
```bash
# Connect to PostgreSQL
psql postgres

# Create database
CREATE DATABASE cardiomed_clinic;

# Create user with password
CREATE USER cardiomed_user WITH PASSWORD 'your_secure_password';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cardiomed_clinic TO cardiomed_user;

# Exit psql
\q
```

### 4. Environment Configuration

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```env
# Server Configuration
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cardiomed_clinic
DB_USER=cardiomed_user
DB_PASSWORD=your_secure_password
DATABASE_URL=postgresql://cardiomed_user:your_secure_password@localhost:5432/cardiomed_clinic

# JWT Configuration (generate a strong secret)
JWT_SECRET=your_super_secret_jwt_key_here_make_it_long_and_random
JWT_EXPIRES_IN=7d

# Email Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

### 5. Generate JWT Secret

Generate a secure JWT secret:
```bash
# Using Node.js
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Or using OpenSSL
openssl rand -hex 64
```

### 6. Run Database Migrations
```bash
npm run migrate
```

### 7. Start the Server

**Development:**
```bash
npm run dev
```

**Production:**
```bash
npm start
```

The server will start on `http://localhost:5000`

## 📊 Database Schema

### Users Table
- User authentication and profile management
- Role-based access control (patient, doctor, admin)

### Appointments Table
- Appointment booking and management
- Status tracking and doctor assignment

### Content Table
- Doctor-uploaded YouTube/Facebook content
- Category filtering and publishing controls

### Reviews Table
- Patient reviews and ratings
- Moderation and verification system

### Contact Messages Table
- Contact form submissions
- Status tracking for customer service

## 🔗 API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/profile` - Get user profile
- `PUT /api/auth/profile` - Update user profile
- `PUT /api/auth/change-password` - Change password

### Appointments
- `POST /api/appointments` - Book appointment
- `GET /api/appointments` - Get all appointments (admin/doctor)
- `GET /api/appointments/my-appointments` - Get user appointments
- `GET /api/appointments/:id` - Get single appointment
- `PATCH /api/appointments/:id/status` - Update appointment status
- `PATCH /api/appointments/:id/cancel` - Cancel appointment
- `DELETE /api/appointments/:id` - Delete appointment (admin)
- `GET /api/appointments/stats/overview` - Get appointment statistics

### Content Management
- `GET /api/content` - Get published content (public)
- `GET /api/content/admin` - Get all content (admin/doctor)
- `POST /api/content` - Create content (doctor/admin)
- `PUT /api/content/:id` - Update content (doctor/admin)
- `PATCH /api/content/:id/publish` - Toggle publish status
- `DELETE /api/content/:id` - Delete content (admin)
- `GET /api/content/meta/categories` - Get content categories
- `GET /api/content/stats/overview` - Get content statistics

### Reviews
- `GET /api/reviews` - Get published reviews (public)
- `POST /api/reviews` - Submit review
- `GET /api/reviews/my-reviews` - Get user reviews
- `PUT /api/reviews/:id` - Update review
- `PATCH /api/reviews/:id/publish` - Publish/unpublish review
- `DELETE /api/reviews/:id` - Delete review
- `GET /api/reviews/stats/overview` - Get review statistics

### Contact Messages
- `POST /api/contact` - Submit contact message (public)
- `GET /api/contact` - Get all messages (admin/doctor)
- `GET /api/contact/:id` - Get single message
- `PATCH /api/contact/:id/status` - Update message status
- `DELETE /api/contact/:id` - Delete message (admin)
- `GET /api/contact/stats/overview` - Get contact statistics

### Health Check
- `GET /api/health` - Server health check

## 🔐 Authentication & Authorization

### JWT Token Format
```javascript
{
  "id": 1,
  "email": "user@example.com",
  "role": "patient"
}
```

### Authorization Header
```
Authorization: Bearer <your_jwt_token>
```

### User Roles
- **patient**: Can book appointments, submit reviews, view own data
- **doctor**: Can manage content, view appointments and reviews
- **admin**: Full access to all resources

## 🛡️ Security Features

- **Rate Limiting**: 100 requests per 15 minutes per IP
- **CORS Protection**: Configured for frontend domain
- **Helmet**: Security headers and protection
- **Input Validation**: Joi schema validation
- **SQL Injection Protection**: Parameterized queries
- **Password Hashing**: bcrypt with salt rounds
- **JWT Security**: Secure token generation and validation

## 🗄️ Database Management

### Run Migrations
```bash
npm run migrate
```

### Seed Database (if needed)
```bash
npm run seed
```

### Connect to Database
```bash
psql postgresql://cardiomed_user:your_password@localhost:5432/cardiomed_clinic
```

## 📝 Logging

The server uses Morgan for request logging. Logs include:
- HTTP method and URL
- Response status code
- Response time
- IP address and user agent

## 🚨 Error Handling

- Centralized error handling middleware
- Proper HTTP status codes
- Detailed error messages in development
- Generic error messages in production
- Database error handling and connection recovery

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 5000 |
| `NODE_ENV` | Environment | development |
| `CLIENT_URL` | Frontend URL | http://localhost:5173 |
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_NAME` | Database name | cardiomed_clinic |
| `DB_USER` | Database user | - |
| `DB_PASSWORD` | Database password | - |
| `JWT_SECRET` | JWT signing secret | - |
| `JWT_EXPIRES_IN` | Token expiration | 7d |

## 🧪 Testing

### Health Check
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "OK",
  "timestamp": "2025-01-17T02:58:49.000Z",
  "uptime": 123.456
}
```

### Test Authentication
```bash
# Register a new user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "full_name": "Test User"
  }'
```

## 🚀 Deployment

### Production Setup

1. **Set environment to production:**
```env
NODE_ENV=production
```

2. **Use a production database:**
```env
DATABASE_URL=postgresql://user:password@your-db-host:5432/dbname
```

3. **Configure proper CORS:**
```env
CLIENT_URL=https://your-frontend-domain.com
```

4. **Start with PM2:**
```bash
npm install -g pm2
pm2 start server.js --name cardiomed-api
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

Build and run:
```bash
docker build -t cardiomed-server .
docker run -p 5000:5000 --env-file .env cardiomed-server
```

## 📈 Monitoring

- Monitor server health via `/api/health` endpoint
- Check database connection status
- Monitor API response times and error rates
- Use tools like PM2 for process monitoring

## 🤝 Contributing

1. Follow the established code structure
2. Add proper validation for new endpoints
3. Include error handling
4. Update this README for new features
5. Test all endpoints before committing

## 📄 License

This project is part of the CardioMed Clinic application.
