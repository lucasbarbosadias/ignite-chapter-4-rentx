import { NextFunction, Request, Response } from 'express';
import { verify } from 'jsonwebtoken';

import { AppError } from '../errors/AppError';
import { UsersRepository } from '../modules/accounts/repositories/implementations/UsersRepository';

interface IPayload {
  sub: string;
}

export async function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction,
) {
  const authHeader = request.headers.authorization;

  if (!authHeader) {
    throw new AppError('Token missing', 401);
  }

  // o split vai quebrar em duas partes após um espaço, ficando [0] = 'Bearer' e [1] = '3e44ca...'
  // passando o [, token] ignoramos o [0] e pegamos o [1] atribuindo a variável token
  const [, token] = authHeader.split(' ');

  try {
    const { sub: user_id } = verify(token, '3e44cae1aa332b5813823f09f7c85bd8')as IPayload;

    const usersRepository = new UsersRepository();

    const user = await usersRepository.findById(user_id);

    if (!user) {
      throw new AppError('User does not exists.', 401);
    }

    request.user = {
      id: user_id,
    };

    next();
  } catch {
    throw new AppError('Invalid token.', 401);
  }
}
