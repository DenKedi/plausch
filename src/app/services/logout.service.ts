import { Injectable, inject } from '@angular/core';
import { CryptoService } from './crypto.service';

@Injectable({
  providedIn: 'root'
})
export class LogoutService {
  private cryptoService = inject(CryptoService);

  public logout(): void {
    localStorage.removeItem('authToken');
    
    // Clear encryption keys from memory
    this.cryptoService.clearKeys();
    
    console.log('🔓 Logged out and cleared encryption keys');
  }
}
