class AppError extends Error {
    statusCode: number;
    status: string;
    isOperational: boolean;
  
    constructor(message: string, statusCode: number) {
      // Call the constructor of the Error class and pass the error message to it
      super(message);
  
      // Set the status code and status properties
      this.statusCode = statusCode;
      this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
  
      // Set the isOperational property to true
      this.isOperational = true;
  
      // Capture the stack trace of the error
      Error.captureStackTrace(this, this.constructor);
    }
  }
  
  export default AppError;
  