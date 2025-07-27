import { query } from '../config/database.js';

const migrations = [
  // Users table for authentication
  `CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'patient',
    phone VARCHAR(20),
    date_of_birth DATE,
    gender VARCHAR(10),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,

  // Appointments table
  `CREATE TABLE IF NOT EXISTS appointments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    patient_name VARCHAR(255) NOT NULL,
    patient_email VARCHAR(255) NOT NULL,
    patient_phone VARCHAR(20) NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    hospital VARCHAR(255) NOT NULL,
    doctor_name VARCHAR(255),
    patient_age INTEGER,
    gender VARCHAR(10),
    symptoms TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,

  // Content table for doctor uploads
  `CREATE TABLE IF NOT EXISTS content (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    url VARCHAR(1000) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    category VARCHAR(100),
    tags TEXT[],
    is_published BOOLEAN DEFAULT false,
    created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,

  // Reviews table
  `CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    patient_name VARCHAR(255) NOT NULL,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    review_text TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT false,
    is_published BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,

  // Contact messages table
  `CREATE TABLE IF NOT EXISTS contact_messages (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    message TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'new',
    responded_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,

  // Create indexes for better performance
  `CREATE INDEX IF NOT EXISTS idx_appointments_date ON appointments(appointment_date)`,
  `CREATE INDEX IF NOT EXISTS idx_appointments_user ON appointments(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_content_published ON content(is_published)`,
  `CREATE INDEX IF NOT EXISTS idx_reviews_published ON reviews(is_published)`,
  `CREATE INDEX IF NOT EXISTS idx_contact_status ON contact_messages(status)`,

  // Create updated_at trigger function
  `CREATE OR REPLACE FUNCTION update_updated_at_column()
   RETURNS TRIGGER AS $$
   BEGIN
     NEW.updated_at = CURRENT_TIMESTAMP;
     RETURN NEW;
   END;
   $$ language 'plpgsql'`,

  // Add triggers for updated_at
  `CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
   FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`,

  `CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON appointments
   FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`,

  `CREATE TRIGGER update_content_updated_at BEFORE UPDATE ON content
   FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`,

  `CREATE TRIGGER update_reviews_updated_at BEFORE UPDATE ON reviews
   FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`
];

async function runMigrations() {
  console.log('🔄 Running database migrations...');
  
  try {
    for (const migration of migrations) {
      await query(migration);
    }
    console.log('✅ All migrations completed successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  }
}

// Run migrations if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runMigrations();
}

export default runMigrations;
