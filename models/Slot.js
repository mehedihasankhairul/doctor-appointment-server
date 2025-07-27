import mongoose from 'mongoose';

const slotSchema = new mongoose.Schema({
  hospital_id: {
    type: String,
    required: true,
    trim: true
  },
  hospital_name: {
    type: String,
    required: true,
    trim: true
  },
  date: {
    type: String, // Format: YYYY-MM-DD
    required: true
  },
  time_slot: {
    type: String, // Format: "03:00 PM - 04:00 PM"
    required: true,
    trim: true
  },
  start_time: {
    type: String, // Format: "15:00"
    required: true
  },
  end_time: {
    type: String, // Format: "16:00" 
    required: true
  },
  max_appointments: {
    type: Number,
    default: 20,
    min: 1
  },
  current_appointments: {
    type: Number,
    default: 0,
    min: 0
  },
  is_available: {
    type: Boolean,
    default: true
  },
  appointment_ids: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment'
  }]
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

// Compound indexes for performance
slotSchema.index({ hospital_id: 1, date: 1, start_time: 1 }, { unique: true });
slotSchema.index({ date: 1, is_available: 1 });
slotSchema.index({ hospital_id: 1, date: 1, is_available: 1 });

// Method to check if slot is available
slotSchema.methods.isSlotAvailable = function() {
  return this.is_available && this.current_appointments < this.max_appointments;
};

// Method to book an appointment in this slot
slotSchema.methods.bookAppointment = function(appointmentId) {
  if (!this.isSlotAvailable()) {
    throw new Error('Slot is not available for booking');
  }
  
  this.appointment_ids.push(appointmentId);
  this.current_appointments = this.appointment_ids.length;
  
  if (this.current_appointments >= this.max_appointments) {
    this.is_available = false;
  }
  
  return this.save();
};

// Method to cancel an appointment from this slot
slotSchema.methods.cancelAppointment = function(appointmentId) {
  const appointmentIndex = this.appointment_ids.indexOf(appointmentId);
  if (appointmentIndex === -1) {
    throw new Error('Appointment not found in this slot');
  }
  
  this.appointment_ids.splice(appointmentIndex, 1);
  this.current_appointments = this.appointment_ids.length;
  
  // Re-enable slot if it was disabled due to capacity
  if (this.current_appointments < this.max_appointments) {
    this.is_available = true;
  }
  
  return this.save();
};

const Slot = mongoose.model('Slot', slotSchema);

export default Slot;
