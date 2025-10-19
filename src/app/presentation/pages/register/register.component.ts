import { Component } from '@angular/core';
import { Router, RouterLink } from "@angular/router";
import { RegisterService } from "../../../services/register.service";
import { InputFormComponent } from "../../ui-components/input-form/input-form.component";
import { HeaderComponent } from "../../ui-components/header/header.component";
import { FooterComponent } from "../../ui-components/footer/footer.component";

@Component({
  selector: 'app-register',
  imports: [RouterLink, InputFormComponent, HeaderComponent, FooterComponent],
  templateUrl: './register.component.html',
  standalone: true,
  styleUrl: './register.component.scss'
})
export class RegisterComponent {
  public errorMessage = '';
  public successMessage = '';
  public redirectToLogin = false;
  
  public constructor(
    private registerService: RegisterService,
    private router: Router
  ) {}

  public register($event: { name: string, email: string; password: string }): void {
    this.errorMessage = '';
    this.successMessage = '';
    this.redirectToLogin = false;

    this.registerService.register($event.name, $event.email, $event.password)
      .then(response => {
        if (response.userStatus === 'confirmed') {
          // User already confirmed - redirect to login after 3 seconds
          this.successMessage = response.msg;
          this.redirectToLogin = true;
          setTimeout(() => {
            this.router.navigate(['/login']);
          }, 3000);
        } else if (response.userStatus === 'unconfirmed') {
          // User exists but unconfirmed - email resent
          this.successMessage = response.msg;
        } else {
          // New registration successful
          this.successMessage = response.msg;
        }
      })
      .catch((error) => {
        this.errorMessage = error.message || 'Fehler beim Registrieren';
      });
  }
}
