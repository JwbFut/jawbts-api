import * as z from "zod";

export const UpdateUserSchema = z
    .object({
        email: z
            .email()
            .max(254)
            .refine(
                (value) =>
                    !value.toLowerCase().endsWith("@placeholder.jawbts.org"),
                { message: "Reserved email domain" },
            )
            .transform((value) => value.toLowerCase())
            .meta({ description: "New email address" }),
    })
    .meta({ id: "UpdateUser" });
