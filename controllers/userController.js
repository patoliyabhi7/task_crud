const User = require('./../model/userModel')
const Task = require('./../model/taskModel')
const sendEmail = require('./../utils/email')
const appError = require('./../utils/appError')
const catchAsync = require('./../utils/catchAsync')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { response } = require('express')

const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);
    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
        ),
        secure: true,
        httpOnly: true,
    };
    res.cookie('jwt', token, cookieOptions);

    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token,
        statusCode,
        response: {
            user,
        },
    });
};

exports.verifyJWT = async (req, res, next) => {
    try {
        let token;

        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith("Bearer ")) {
            token = authHeader.split(" ")[1];
        }

        if (!token) {
            return res.status(401).json({ statusMessage: "User not logged in or Unauthorized request", statusCode: 401 });
        }
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decodedToken.id).select("-password");

        if (!user) {
            return res.status(404).json({ statusMessage: "User not found", statusCode: 404 });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ statusMessage: "Invalid access token", statusCode: 401 });
    }
};

exports.register = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        username: req.body.username,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        gender: req.body.gender,
    })
    res.status(200).json({
        statusMessage: 'Signup successful',
        statusCode: 200,
        response: {
            user: newUser
        }
    })
})

exports.login = catchAsync(async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                status: 'Failed',
                statusCode: 400,
                statusMessage: 'Please enter email and password'
            })
        }
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.correctPassword(password, user.password))) {
            return res.status(400).json({
                status: 'Login failed',
                statusCode: 400,
                statusMessage: 'Incorrect email or password'
            })
        }

        createSendToken(user, 200, res);

    } catch (error) {
        res.status(400).json({
            statusCode: 400,
            status: 'Failed',
            statusMessage: error.message
        })
    }
})

exports.forgotPassword = catchAsync(async (req, res, next) => {
    try {
        if (!req.body.email) {
            return res.status(400).json({
                status: 'Failed',
                statusCode: 400,
                statusMessage: 'Please enter your email'
            })
        }
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({
                status: 'Failed',
                statusCode: 404,
                statusMessage: 'User not found with this email id'
            })
        }
        const otp = Math.floor(1000 + Math.random() * 9000);
        res.cookie("otp", { email: req.body.email, otp }, { maxAge: 300000 });


        const message = `Reset your password OTP: ${otp} \n This OTP is valid for 5 minutes Only`;
        try {
            await sendEmail({
                email: user.email,
                subject: 'Password Reset OTP',
                message
            })
            res.status(200).json({
                status: 'Email sent successfully',
                statusCode: 200,
                statusMessage: 'Password reset OTP sent to your email'
            })
        } catch (error) {
            res.clearCookie('otp');
            res.status(400).json({
                statusCode: 400,
                status: 'Error while sending OTP',
                statusMessage: error.message
            })

        }
    } catch (error) {
        res.status(400).json({
            statusCode: 400,
            status: 'Error while resetting password',
            statusMessage: error.message
        })
    }
})

exports.verifyOTP = catchAsync(async (req, res, next) => {
    try {
        const enteredOtp = req.body.otp;
        const otpData = req.cookies.otp;

        if (!otpData) {
            return res.status(400).json({
                statusCode: 400,
                statusMessage: 'OTP expired or not found'
            });
        }

        const { email, otp } = otpData; // otpData is already an object

        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(400).json({
                statusMessage: 'User not found with this email',
                statusCode: 400
            });
        }

        if (!enteredOtp) {
            return res.status(400).json({
                statusMessage: 'Please enter the OTP',
                statusCode: 400
            });
        }

        if (otpData.email !== req.body.email) {
            return res.status(400).json({
                statusMessage: 'Email does not match, unauthorized request',
                statusCode: 400
            });
        }

        if (otp !== enteredOtp || email !== req.body.email) {
            return res.status(400).json({
                statusMessage: 'OTP Incorrect or expired',
                statusCode: 400
            });
        }

        user.password = req.body.password;
        user.confirmPassword = req.body.confirmPassword;
        await user.save();
        res.clearCookie('otp');

        createSendToken(user, 200, res);
    } catch (error) {
        res.status(400).json({
            status: 'Error while verifying OTP',
            statusCode: 400,
            statusMessage: error.message
        });
    }
});

exports.updatePassword = catchAsync(async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).select('+password');
        if (!user) {
            return res.status(400).json({
                status: 'Failed',
                statusCode: 400,
                statusMessage: 'User not found or not logged in'
            })
        }
        if (!req.body.password || !req.body.confirmPassword || !req.body.currentPassword) {
            return res.status(400).json({
                statusMessage: 'Please enter current, new and confirm password',
                statusCode: 400
            })
        }
        if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
            return res.status(400).json({
                statusMessage: 'Current password is incorrect',
                statusCode: 400
            })
        }
        user.password = req.body.password;
        user.confirmPassword = req.body.confirmPassword;
        await user.save();
        createSendToken(user, 200, res);
    } catch (error) {
        res.status(400).json({
            status: 'Error while updating password',
            statusMessage: error.message,
            statusCode: 400
        })
    }
})

exports.viewProfile = catchAsync(async (req, res, next) => {
    res.status(200).json({
        status: 'success',
        statusMessage: 'User profile fetched successfully',
        statusCode: 200,
        response: {
            user: req.user
        }
    });
});

exports.createTask = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return res.status(400).json({
            statusMessage: 'User not found or not logged in',
            statusCode: 400
        })
    }
    const { title, description, status, priority, deadline } = req.body;
    const newTask = await Task.create({
        title,
        description,
        status,
        priority,
        deadline,
        user_id: req.user._id
    });
    if (!newTask) {
        return res.status(400).json({
            statusMessage: 'Error while creating task',
            statusCode: 400
        });
    }

    res.status(200).json({
        statusMessage: 'Task created successfully',
        statusCode: 200,
        response: {
            task: newTask
        }
    });
});

exports.getCurrentUserTask = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return res.status(400).json({
            statusMessage: 'User not found or not logged in',
            statusCode: 400
        })
    }
    const tasks = await Task.find({ user_id: req.user.id });
    if (!tasks) {
        return res.status(400).json({
            statusMessage: 'No tasks found for this user'
        });
    }
    res.status(200).json({
        statusMessage: 'Tasks fetched successfully',
        statusCode: 200,
        response: {
            tasks
        }
    });
});

exports.getAllTasks = catchAsync(async (req, res, next) => {
    const tasks = await Task.find();
    if (!tasks) {
        return res.status(400).json({
            statusMessage: 'No tasks found',
            statusCode: 400
        });
    }
    res.status(200).json({
        statusMessage: 'Tasks fetched successfully',
        statusCode: 200,
        response: {
            tasks
        }
    });
});

exports.updateTask = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return res.status(400).json({
            statusMessage: 'User not found or not logged in',
            statusCode: 400
        })
    }
    const task = await Task.findById(req.params.id);
    if (!task) {
        return res.status(400).json({
            statusMessage: 'Task not found',
            statusCode: 400
        });
    }
    if (task.user_id.toString() !== req.user.id) {
        return res.status(401).json({
            statusMessage: 'Unauthorized request!, You are not authorized to update this task.',
            statusCode: 401
        });
    }
    const { title, description, status, priority, deadline } = req.body;
    const updatedTask = await Task.findByIdAndUpdate(req.params.id, {
        title,
        description,
        status,
        priority,
        deadline
    }, {
        new: true,
        runValidators: true
    });
    if (!updatedTask) {
        return res.status(400).json({
            statusMessage: 'Error while updating task',
            statusCode: 400
        });
    }

    res.status(200).json({
        statusMessage: 'Task updated successfully',
        statusCode: 200,
        response: {
            task: updatedTask
        }
    });
});

exports.deleteTask = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return res.status(400).json({
            status: 'Failed',
            statusCode: 400,
            statusMessage: 'User not found or not logged in'
        })
    }
    const task = await Task.findById(req.params.id);
    if (!task) {
        return res.status(400).json({
            statusMessage: 'Task not found',
            statusCode: 400
        });
    }
    if (task.user_id.toString() !== req.user.id) {
        return res.status(401).json({
            statusCode: 401,
            statusMessage: 'Unauthorized request!, You are not authorized to delete this task.'
        });
    }
    await Task.findByIdAndDelete(req.params.id);
    res.status(200).json({
        statusMessage: 'Task deleted successfully',
        statusCode: 200
    });
});