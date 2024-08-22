const User = require('./../model/userModel')
const Task = require('./../model/taskModel')
const sendEmail = require('./../utils/email')
const appError = require('./../utils/appError')
const catchAsync = require('./../utils/catchAsync')
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

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
        data: {
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
            return res.status(401).json({ message: "User not logged in or Unauthorized request" });
        }
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decodedToken.id).select("-password");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: "Invalid access token" });
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
        status: 'Signup successful',
        data: {
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
                message: 'Please enter email and password'
            })
        }
        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await user.correctPassword(password, user.password))) {
            return res.status(400).json({
                status: 'Login failed',
                message: 'Incorrect email or password'
            })
        }

        createSendToken(user, 200, res);

    } catch (error) {
        res.status(400).json({
            status: 'Failed',
            message: error.message
        })
    }
})

exports.forgotPassword = catchAsync(async (req, res, next) => {
    try {
        if (!req.body.email) {
            return res.status(400).json({
                status: 'Failed',
                message: 'Please enter your email'
            })
        }
        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(404).json({
                status: 'Failed',
                message: 'User not found with this email id'
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
                message: 'Password reset OTP sent to your email'
            })
        } catch (error) {
            res.clearCookie('otp');
            res.status(400).json({
                status: 'Error while sending OTP',
                message: error.message
            })

        }
    } catch (error) {
        res.status(400).json({
            status: 'Error while resetting password',
            message: error.message
        })
    }
})

exports.verifyOTP = catchAsync(async (req, res, next) => {
    try {
        const enteredOtp = req.body.otp;
        const otpData = req.cookies.otp;

        if (!otpData) {
            return res.status(400).json({
                message: 'OTP expired or not found'
            });
        }

        const { email, otp } = otpData; // otpData is already an object

        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            return res.status(400).json({
                message: 'User not found with this email'
            });
        }

        if (!enteredOtp) {
            return res.status(400).json({
                message: 'Please enter the OTP'
            });
        }

        if(otpData.email !== req.body.email) {
            return res.status(400).json({
                message: 'Email does not match, unauthorized request'
            });
        }

        if (otp !== enteredOtp || email !== req.body.email) {
            return res.status(400).json({
                message: 'OTP Incorrect or expired'
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
            message: error.message
        });
    }
});

exports.updatePassword = catchAsync(async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).select('+password');
        if (!user) {
            return res.status(400).json({
                message: 'User not found or not logged in'
            })
        }
        if (!req.body.password || !req.body.confirmPassword || !req.body.currentPassword) {
            return res.status(400).json({
                message: 'Please enter current, new and confirm password'
            })
        }
        if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
            return res.status(400).json({
                message: 'Current password is incorrect'
            })
        }
        user.password = req.body.password;
        user.confirmPassword = req.body.confirmPassword;
        await user.save();
        createSendToken(user, 200, res);
    } catch (error) {
        res.status(400).json({
            status: 'Error while updating password',
            message: error.message
        })
    }
})

exports.viewProfile = catchAsync(async (req, res, next) => {
    res.status(200).json({
        status: 'success',
        message: 'User profile fetched successfully',
        data: {
            user: req.user
        }
    });
});

exports.createTask = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.user.id);
    if (!user) {
        return res.status(400).json({
            message: 'User not found or not logged in'
        })
    }
    const { title, description, status, priority, deadline } = req.body;
    const newTask = await Task.create({
        title,
        description,
        status,
        priority,
        deadline,
        user_id: req.user.id
    });
    if (!newTask) {
        return res.status(400).json({
            message: 'Error while creating task'
        });
    }

    res.status(200).json({
        status: 'Task created successfully',
        data: {
            task: newTask
        }
    });
});