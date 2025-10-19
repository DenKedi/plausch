import { Injectable } from '@angular/core';
import api from '../utils/api';
import { AxiosError } from 'axios';

export interface RegisterResponse {
  msg: string;
  userStatus?: 'confirmed' | 'unconfirmed';
}

@Injectable({
  providedIn: 'root',
})
export class RegisterService {
  public async register(
    name: string,
    email: string,
    password: string
  ): Promise<RegisterResponse> {
    try {
      const response = await api.post(`/api/user/register`, {
        displayed_name: name,
        email,
        password,
      });
      return response.data;
    } catch (error) {
      if (error instanceof AxiosError) {
        const errorData = error.response?.data;
        const status = error.response?.status;

        // 409 means user exists (either confirmed or unconfirmed) - treat as success for UI
        if (status === 409 && errorData?.userStatus) {
          return {
            msg: errorData.msg,
            userStatus: errorData.userStatus,
          };
        }

        // Other errors - throw
        throw new Error(errorData?.msg || 'Ein Fehler ist aufgetreten');
      }

      throw new Error('Ein unerwarteter Fehler ist aufgetreten');
    }
  }
}
