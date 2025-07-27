import mongoose from 'mongoose';

const prescriptionSchema = new mongoose.Schema({
  reference_number: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  appointment_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment',
    required: true
  },
  patient_name: {
    type: String,
    required: true,
    trim: true
  },
  patient_email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  patient_age: {
    type: Number,
    required: true
  },
  diagnosis: {
    type: String,
    required: true,
    trim: true
  },
  medications: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    dosage: {
      type: String,
      required: true,
      trim: true
    },
    frequency: {
      type: String,
      required: true,
      trim: true
    },
    duration: {
      type: String,
      required: true,
      trim: true
    },
    instructions: {
      type: String,
      trim: true
    }
  }],
  doctor_name: {
    type: String,
    required: true,
    trim: true
  },
  doctor_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false
  },
  hospital: {
    type: String,
    required: true,
    trim: true
  },
  issued_date: {
    type: Date,
    default: Date.now
  },
  valid_until: {
    type: Date,
    required: true
  },
  notes: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['active', 'completed', 'expired', 'cancelled'],
    default: 'active'
  },
  next_visit: {
    date: {
      type: Date
    },
    instructions: {
      type: String,
      trim: true
    }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
prescriptionSchema.index({ reference_number: 1 });
prescriptionSchema.index({ appointment_id: 1 });
prescriptionSchema.index({ patient_email: 1 });
prescriptionSchema.index({ status: 1 });
prescriptionSchema.index({ issued_date: -1 });

const Prescription = mongoose.model('Prescription', prescriptionSchema);

export default Prescription;
