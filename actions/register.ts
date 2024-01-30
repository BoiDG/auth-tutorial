"use server";
/**
 * Flow explain at 4:44:42
 */

import { RegisterSchema } from "@/schemas";
import * as z from "zod";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";
import { getUserByEmail } from "@/data/user";
import { generateVerificationToken } from "@/lib/token";
import { sendVerificationEmail } from "@/lib/mail";

export const register = async (values: z.infer<typeof RegisterSchema>) => {
    //safeparse: parse data safely without throwing an error.
    const validatedFields = RegisterSchema.safeParse(values);

    if (!validatedFields.success) {
        return { error: "Invalid fields!" };
    }

    const { name, email, password } = validatedFields.data;
    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await getUserByEmail(email);
    // console.log("User:::", existingUser)
    if (existingUser) {
        return { error: "Email already in use!" }
    }

    await db.user.create({
        data: {
            name,
            email,
            password: hashedPassword,
        }
    });

    const verificationToken = await generateVerificationToken(email);

    await sendVerificationEmail(
        verificationToken.email,
        verificationToken.token
    )

    return { success: "Confirmation email sent" };
};

