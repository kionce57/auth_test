import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/react';
import { GoogleLoginButton } from './GoogleLoginButton';

describe('GoogleLoginButton', () => {
  beforeEach(() => {
    // Mock window.location
    delete (window as any).location;
    (window as any).location = { href: '', pathname: '/login' };

    // Mock sessionStorage
    vi.spyOn(Storage.prototype, 'setItem');
  });

  it('renders google login button', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    expect(button).toBeTruthy();
    expect(button.textContent).toContain('Google');
  });

  it('redirects to oauth endpoint on click', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    fireEvent.click(button);

    expect(window.location.href).toBe('/api/v2/sessions/google/login');
  });

  it('saves current location before redirect', () => {
    const { getByRole } = render(<GoogleLoginButton />);
    const button = getByRole('button');

    fireEvent.click(button);

    expect(sessionStorage.setItem).toHaveBeenCalledWith(
      'redirectAfterLogin',
      expect.any(String)
    );
  });
});
