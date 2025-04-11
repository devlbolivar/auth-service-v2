declare global {
  namespace Express {
    interface Request {
      user?: any; // You can replace `any` with a more specific type
    }
  }
}

export {};
