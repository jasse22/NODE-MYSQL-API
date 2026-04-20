export default function validateRequest(req: any, next: any, schema: any) {
    const options = {
        abortEarly: false,    // Return all errors, not just the first one
        allowUnknown: true,   // Allow fields not in the schema
        stripUnknown: true    // Remove fields not in the schema
    };
    
    const { error, value } = schema.validate(req.body, options);
    
    if (error) {
        // Format error message with all validation issues
        const errorMessage = `Validation error: ${error.details.map((x: any) => x.message).join(', ')}`;
        next(errorMessage);
    } else {
        // Replace request body with validated (and stripped) value
        req.body = value;
        next();
    }
}