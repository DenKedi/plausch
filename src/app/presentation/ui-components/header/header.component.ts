import { Component, input } from '@angular/core';
import { CtaButtonComponent } from '../cta-button/cta-button.component';
import { HelpModalComponent } from '../help-modal/help-modal.component';
import { LogoutService } from '../../../services/logout.service';
import { Router } from '@angular/router';
import { User } from '../../../data-domain/models/user.model';

@Component({
  selector: 'app-header',
  imports: [CtaButtonComponent, HelpModalComponent],
  templateUrl: './header.component.html',
  standalone: true,
  styleUrl: './header.component.scss',
})
export class HeaderComponent {
  public user = input<User>();
  public showHelpModal = false;

  public constructor(
    private logoutService: LogoutService,
    private router: Router
  ) {}

  public redirectToHome(): void {
    this.router.navigate(['/home']);
  }

  public isLoggedIn(): boolean {
    return localStorage.getItem('authToken') !== null;
  }

  public logout(): void {
    this.logoutService.logout();
    this.router.navigate(['/home']);
  }

  public openHelp(): void {
    this.showHelpModal = true;
  }

  public closeHelp(): void {
    this.showHelpModal = false;
  }
}
