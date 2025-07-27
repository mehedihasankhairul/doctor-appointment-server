import crypto from 'crypto';
import dayjs from 'dayjs';

/**
 * Generate a unique reference number for appointments and prescriptions
 * Format: YYYY-MMDD-XXXX-YYYY
 * Where YYYY = year, MMDD = month+day, XXXX = random 4 digit, YYYY = sequential 4 digit
 */
export const generateReferenceNumber = (type = 'APT') => {
  const now = dayjs();
  const year = now.format('YYYY');
  const monthDay = now.format('MMDD');
  
  // Generate random 4-digit number
  const random = crypto.randomInt(1000, 9999);
  
  // Generate timestamp-based suffix for uniqueness
  const timestamp = now.format('HHmm');
  
  const prefix = type === 'PRESCRIPTION' ? 'RX' : 'APT';
  
  return `${prefix}-${year}-${monthDay}-${random}-${timestamp}`;
};

/**
 * Validate reference number format
 */
export const isValidReferenceNumber = (refNumber) => {
  const pattern = /^(APT|RX)-\d{4}-\d{4}-\d{4}-\d{4}$/;
  return pattern.test(refNumber);
};

/**
 * Generate prescription reference number
 */
export const generatePrescriptionReferenceNumber = () => {
  return generateReferenceNumber('PRESCRIPTION');
};

/**
 * Parse reference number to extract information
 */
export const parseReferenceNumber = (refNumber) => {
  if (!isValidReferenceNumber(refNumber)) {
    return null;
  }
  
  const parts = refNumber.split('-');
  return {
    type: parts[0] === 'APT' ? 'appointment' : 'prescription',
    year: parts[1],
    month: parts[2].substring(0, 2),
    day: parts[2].substring(2, 4),
    random: parts[3],
    timestamp: parts[4]
  };
};

/**
 * Format date for display
 */
export const formatDate = (date, format = 'YYYY-MM-DD') => {
  return dayjs(date).format(format);
};

/**
 * Check if date is in the past
 */
export const isPastDate = (date) => {
  return dayjs(date).isBefore(dayjs(), 'day');
};

/**
 * Check if date is today
 */
export const isToday = (date) => {
  return dayjs(date).isSame(dayjs(), 'day');
};

/**
 * Get days difference from today
 */
export const getDaysFromToday = (date) => {
  return dayjs(date).diff(dayjs(), 'day');
};

/**
 * Generate a unique file name for uploads
 */
export const generateFileName = (originalName, prefix = '') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex');
  const extension = originalName.split('.').pop();
  
  return `${prefix}${timestamp}-${random}.${extension}`;
};

/**
 * Sanitize string for database storage
 */
export const sanitizeString = (str) => {
  if (typeof str !== 'string') return str;
  return str.trim().replace(/[<>]/g, '');
};

/**
 * Validate email format
 */
export const isValidEmail = (email) => {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailPattern.test(email);
};

/**
 * Validate phone number (basic validation)
 */
export const isValidPhone = (phone) => {
  const phonePattern = /^[+]?[\d\s\-\(\)]{10,}$/;
  return phonePattern.test(phone);
};

/**
 * Capitalize first letter of each word
 */
export const capitalizeWords = (str) => {
  if (typeof str !== 'string') return str;
  return str.replace(/\w\S*/g, (txt) => 
    txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
  );
};

export default {
  generateReferenceNumber,
  generatePrescriptionReferenceNumber,
  isValidReferenceNumber,
  parseReferenceNumber,
  formatDate,
  isPastDate,
  isToday,
  getDaysFromToday,
  generateFileName,
  sanitizeString,
  isValidEmail,
  isValidPhone,
  capitalizeWords
};
