const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Please enter the title of the task'],
    },
    description: {
        type: String,
        required: [true, 'Please enter the description of the task'],
    },
    status: {
        type: String,
        enum: ['pending', 'in_progress', 'completed'],
        default: 'pending',
    },
    priority: {
        type: String,
        enum: ['low', 'medium', 'high'],
        required: [true, 'Please select the priority of the task'],
    },
    deadline: {
        type: Date,
        required: [true, 'Please provide a deadline for the task'],
    },
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required'],
    },
    createDate: {
        type: Date,
        default: Date.now,
    }
});

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;
