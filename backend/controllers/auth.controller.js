import bcrypt from 'bcryptjs';

import User from '../models/user.model.js';
import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";

export const signup = async (req, res) => {
    try {
        const { fullName, username, email, password } = req.body;

        // Validar formato de email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).send({ message: 'Invalid email format' });
        }

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: 'Username already exists' });
        }

        // Verificar si el email ya está en uso
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).send({ message: 'Email already exists' });
        }

        if(password.minLength < 6){
            return res.status(400).send({ message: 'Password must be at least 6 characters long' });
        }

        // Hashear la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Crear un nuevo usuario
        const newUser = new User({
            fullName,
            username,
            email,
            password: hashedPassword,
        });

        // Guardar el usuario y generar un token
        await newUser.save();
        generateTokenAndSetCookie(newUser._id, res);

        // Enviar la respuesta con el usuario creado
        return res.status(201).json({
            _id: newUser._id,
            fullName: newUser.fullName,
            username: newUser.username,
            email: newUser.email,
            followers: newUser.followers,
            following: newUser.following,
            profileImg: newUser.profileImg,
            coverImg: newUser.coverImg,
        });

    } catch (error) {
        console.error(error);
        return res.status(500).send({ error: 'Internal server error' });
    }
};

export const login = async (req, res) => { 
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        const isPasswordCorrect = await bcrypt.compare(password, user?.password || "");

        if(!user || !isPasswordCorrect){
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        generateTokenAndSetCookie(user._id, res);

        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            username: user.username,
            email: user.email,
            followers: user.followers,
            following: user.following,
            profileImg: user.profileImg,
            coverImg: user.coverImg,
        });

    } catch (error) {
        console.error("Error in login controller", error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
 };


export const logout = async (req, res) => { 
    try {
        res.cookie("jwt", "", {maxAge: 0})
        res.status(200).json({ message: 'Logout successful' }); 
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
 };

 export const getMe = async (req, res) => {
    try {
        const  user =  await User.findById(req.user._id).select("-password");
        res.status(200).json(user);
    } catch (error) {
        console.log("Error in getMe controller", error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};