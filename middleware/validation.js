import Joi from 'joi';

// User registration validation
export const validateRegistration = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    full_name: Joi.string().min(2).max(255).required(),
    phone: Joi.string().optional(),
    date_of_birth: Joi.date().optional(),
    gender: Joi.string().valid('male', 'female', 'other').optional(),
    address: Joi.string().optional()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  next();
};

// User login validation
export const validateLogin = (req, res, next) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  next();
};

// Appointment validation
export const validateAppointment = (req, res, next) => {
  const schema = Joi.object({
    patient_name: Joi.string().min(2).max(255).required(),
    patient_email: Joi.string().email().required(),
    patient_phone: Joi.string().required(),
    appointment_date: Joi.date().min('now').required(),
    appointment_time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).required(),
    hospital: Joi.string().required(),
    patient_age: Joi.number().integer().min(0).max(150).optional(),
    gender: Joi.string().valid('male', 'female', 'other').optional(),
    symptoms: Joi.string().max(1000).optional()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  next();
};

// Content validation
export const validateContent = (req, res, next) => {
  const schema = Joi.object({
    title: Joi.string().min(5).max(500).required(),
    description: Joi.string().max(2000).optional(),
    content_url: Joi.string().uri().required(),
    content_type: Joi.string().valid('youtube', 'facebook', 'article', 'image', 'video').required(),
    thumbnail_url: Joi.string().uri().optional(),
    category: Joi.string().max(100).optional(),
    tags: Joi.array().items(Joi.string().max(50)).optional(),
    is_published: Joi.boolean().optional(),
    is_featured: Joi.boolean().optional(),
    metadata: Joi.object({
      duration: Joi.string().optional(),
      file_size: Joi.number().optional(),
      dimensions: Joi.object({
        width: Joi.number().optional(),
        height: Joi.number().optional()
      }).optional()
    }).optional()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  // Additional URL validation for platforms
  const { content_url, content_type } = req.body;
  
  if (content_type === 'youtube') {
    const youtubeRegex = /^(https?:\/\/)?(www\.)?(youtube\.com\/(watch\?v=|embed\/)|youtu\.be\/)/;
    if (!youtubeRegex.test(content_url)) {
      return res.status(400).json({ 
        error: 'Invalid YouTube URL format' 
      });
    }
  }

  if (content_type === 'facebook') {
    const facebookRegex = /^(https?:\/\/)?(www\.)?facebook\.com\//;
    if (!facebookRegex.test(content_url)) {
      return res.status(400).json({ 
        error: 'Invalid Facebook URL format' 
      });
    }
  }

  next();
};

// Review validation
export const validateReview = (req, res, next) => {
  const schema = Joi.object({
    patient_name: Joi.string().min(2).max(255).required(),
    rating: Joi.number().integer().min(1).max(5).required(),
    review_text: Joi.string().min(10).max(1000).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  next();
};

// Contact message validation
export const validateContact = (req, res, next) => {
  const schema = Joi.object({
    full_name: Joi.string().min(2).max(255).required(),
    email: Joi.string().email().required(),
    phone: Joi.string().optional(),
    message: Joi.string().min(10).max(2000).required()
  });

  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: error.details.map(d => d.message) 
    });
  }

  next();
};

// Generic validation middleware
export const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: error.details.map(d => d.message) 
      });
    }
    next();
  };
};
