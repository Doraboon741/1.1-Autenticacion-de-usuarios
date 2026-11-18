<?php

namespace App\Http\Controllers;

use App\Mail\AdminVerificationCodeMail;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;

class AuthController extends Controller
{
    public function showLogin()
    {
        return view('auth.login');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $credentials['email'])->first();

        if (!$user || !Hash::check($credentials['password'], $user->password)) {
            return back()->withErrors([
                'email' => 'Las credenciales ingresadas no son correctas.',
            ])->onlyInput('email');
        }

        // Flujo del empleado. Entra directo este, sin autenticacion
        if ($user->role === 'empleado') {
            Auth::login($user);
            $request->session()->regenerate();
            return redirect()->route('users.index');
        }

        // Flujo de 3 etapas para Administrador
        $code = (string) random_int(100000, 999999);

        $user->forceFill([
            'two_factor_code'       => $code,
            'two_factor_expires_at' => now()->addMinutes(5),
        ])->save();

        // Guarda en la sesión temporal que pasó la etapa 1 (sin autenticar aún)
        $request->session()->put('2fa:user_id', $user->id);

        Mail::to($user->email)->send(new AdminVerificationCodeMail($code));

        return redirect()->route('verify.show')
            ->with('status', 'Se envió un código de verificación a tu correo (vigencia: 5 minutos).');
    }

    public function showVerifyForm(Request $request)
    {
        // Bloquear acceso directo si no completó la autenticación inicial
        if (!$request->session()->has('2fa:user_id')) {
            return redirect()->route('login')
                ->withErrors(['email' => 'Debes iniciar sesión primero para acceder a la verificación.']);
        }

        return view('auth.verify');
    }

    public function verifyCode(Request $request)
    {
        if (!$request->session()->has('2fa:user_id')) {
            return redirect()->route('login');
        }

        $request->validate([
            'code' => 'required|digits:6',
        ]);

        $user = User::findOrFail($request->session()->get('2fa:user_id'));

        // Validar vigencia máxima de 5 minutos
        if (!$user->two_factor_expires_at || now()->greaterThan($user->two_factor_expires_at)) {
            $user->forceFill([
                'two_factor_code'       => null,
                'two_factor_expires_at' => null,
            ])->save();

            $request->session()->forget('2fa:user_id');

            return redirect()->route('login')
                ->withErrors(['email' => 'El código de verificación ha expirado (límite de 5 minutos). Inicia sesión nuevamente.']);
        }

        // Validar coincidencia del código
        if ($request->code !== $user->two_factor_code) {
            return back()->withErrors(['code' => 'El código ingresado es incorrecto.']);
        }

        // Limpiar código e iniciar sesión completa
        $user->forceFill([
            'two_factor_code'       => null,
            'two_factor_expires_at' => null,
        ])->save();

        $request->session()->forget('2fa:user_id');

        Auth::login($user);
        $request->session()->regenerate();

        return redirect()->route('users.index');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }
}
