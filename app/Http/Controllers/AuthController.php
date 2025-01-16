<?php

namespace App\Http\Controllers;

use App\Mail\NewUserConfirmation;
use App\Mail\ResetPassword;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function login(): View {
        return view('auth.login');
    }

    public function authenticate(Request $request): RedirectResponse {

        // Validação do formulário
        $credentials = $request->validate([
            'username' => 'required|min:3|max:30',
            'password' => 'required|regex:/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,32}$/',
        ], [
            'username.required' => 'O usuário é obrigatório.',
            'username.min' => 'O usuário deve ter no mínimo :min caracteres.',
            'username.max' => 'O usuário deve ter no máximo :max caracteres.',
            'password.required' => 'A senha é obrigatória.',
            'password.regex' => 'A senha deve conter pelo menos uma letra e um número, e deve ter entre 8 e 32 caracteres.'
        ]);

        // Verificar se o usuário existe
        $user = User::where('username', $credentials['username'])
            ->where('active', true)
            ->where(function($query) {
                $query->whereNull('blocked_until')
                    ->orWhere('blocked_until', '<=', now());
            })
            ->whereNotNull('email_verified_at') // Garantir que o email esteja verificado
            ->whereNull('deleted_at') // Garantir que o usuário não esteja excluído
            ->first();

        if (!$user) {
            return back()->withInput()->with([
                'invalid_login' => 'Login inválido'
            ]);
        }

        if (!password_verify($credentials['password'], $user->password)) {
            return back()->withInput()->with([
                'invalid_login' => 'Login inválido'
            ]);
        }

        $user->last_login_at = now();
        $user->blocked_until = null;
        $user->save();

        $request->session()->regenerate();
        Auth::login($user);

        return redirect()->route('home');
    }

    public function logout(): RedirectResponse {
        Auth::logout();
        return redirect()->route('login');
    }

    public function register() {
        return view('auth.register');
    }

    public function store_user(Request $request): RedirectResponse | View
    {
        $request->validate(
            [
                'username' => 'required|min:3|max:30|unique:users,username',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:8|max:32|regex:/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,32}$/',
                'password_confirmation' => 'required|same:password'
            ],
            [
                'username.required' => 'O nome de usuário é obrigatório.',
                'username.min' => 'O nome de usuário deve ter no mínimo :min caracteres.',
                'username.max' => 'O nome de usuário deve ter no máximo :max caracteres.',
                'username.unique' => 'O nome de usuário já está em uso.',

                'email.required' => 'O email é obrigatório.',
                'email.email' => 'O email informado não é válido.',
                'email.unique' => 'O email já está em uso.',

                'password.required' => 'A senha é obrigatória.',
                'password.min' => 'A senha deve ter no mínimo :min caracteres.',
                'password.max' => 'A senha deve ter no máximo :max caracteres.',
                'password.regex' => 'A senha deve conter pelo menos uma letra e um número, e deve ter entre 8 e 32 caracteres.',

                'password_confirmation.required' => 'A confirmação de senha é obrigatória.',
                'password_confirmation.same' => 'A confirmação de senha não corresponde à senha digitada.',
            ]
        );

        // Sanitizar email
        $sanitizedEmail = filter_var(trim($request->email), FILTER_VALIDATE_EMAIL);
        if (!$sanitizedEmail) {
            return back()->withInput()->withErrors(['email' => 'O email informado não é válido.']);
        }

        $user = new User();
        $user->username = $request->username;
        $user->email = $sanitizedEmail;
        $user->password = bcrypt($request->password);
        $user->token = Str::random(64);

        $confirmation_link = route('new_user_confirmation', ['token' => $user->token]);

        try {
            Mail::to($user->email)->send(new NewUserConfirmation($user->username, $confirmation_link));
        } catch (\Exception $e) {
            return back()->withInput()->with([
                'server_error' => 'Ocorreu um erro ao enviar o email de confirmação. Tente novamente mais tarde.'
            ]);
        }

        $user->save();

        return view('auth.email_sent', ['email' => $user->email]);
    }

    public function new_user_confirmation($token) {
        //verificar se o token é valido
        $user = User::where('token', $token)->first();
        if(!$user) {
            return redirect()->route('login');
        }

        //confirmar o registreo do usuario
        $user->email_verified_at = Carbon::now();
        $user->token = null;
        $user->active = true;
        $user->save();

        //autenticaçao automatica (login) do usuario confirmado
        Auth::login($user);

        //apresenta uma mensagem de sucesso
        return view('auth.new_user_confirmation');
    }

    public function profile():View {
        return view('auth.profile');
    }

    public function change_password(Request $request)
{
    // Validação do formulário
    $request->validate(
        [
            'current_password' => [
                'required',
                'string',
                'current_password:web' // Valida se a senha atual está correta
            ],
            'new_password' => [
                'required',
                'string',
                'min:8',
                'max:32',
                'regex:/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,32}$/', // Deve conter ao menos uma letra e um número
                'different:current_password' // Nova senha deve ser diferente da atual
            ],
            'new_password_confirmation' => [
                'required',
                'same:new_password' // Confirmação deve coincidir com a nova senha
            ],
        ],
        [
            'current_password.required' => 'A senha atual é obrigatória.',
            'current_password.current_password' => 'A senha atual está incorreta.',

            'new_password.required' => 'A nova senha é obrigatória.',
            'new_password.min' => 'A nova senha deve ter no mínimo :min caracteres.',
            'new_password.max' => 'A nova senha deve ter no máximo :max caracteres.',
            'new_password.regex' => 'A nova senha deve conter pelo menos uma letra e um número.',
            'new_password.different' => 'A nova senha deve ser diferente da senha atual.',

            'new_password_confirmation.required' => 'A confirmação da nova senha é obrigatória.',
            'new_password_confirmation.same' => 'A confirmação da nova senha não corresponde à nova senha digitada.',
        ]
    );

    // vereficar se a password atual (current_password) esta correta
    if(!password_verify($request->current_password, Auth::user()->password)) {
        return back()->with([
            'server_error' => 'A senha atual nao esta correta'
        ]);
    }

    //atualizar a senha na base de dados
    $user = Auth::user();
    $user->password = bcrypt($request->new_password);
    $user->save();


    //atualizar o password na sessao
    Auth::user()->password = $request->new_password;

    // apresentar uma mensagem de sucesso
    return redirect()->route('profile')->with([
        'sucess' => 'A senha foi atualizada com sucesso'
    ]);
}

public function forgot_password():View {
    return view('auth.forgot_password');
}

public function send_reset_password_link(Request $request){
    //form validation
    $request->validate([
        'email' => 'required|email',
    ],
    [
        'email.required' => 'O email é obrigatorio',
        'email.email' => 'O email deve ser um endereço de email válido',
    ]
);

    $generic_message = "Verifique sua caixa de correio para prosseguir com a recuperação de senha";

    //vereficar se email existe
    $user = User::where('email', $request->email)->first();
    if(!$user) {
        return back()->with([
            'server_message' => $generic_message
        ]);
    }

    //criar o link com o token para enviar no email
    $user->token = Str::random(64);

    $token_link = route('reset_password', ['token' => $user->token]);

    //envio de email com link para recuperar a senha
    $result = Mail::to($user->email)->send(new ResetPassword($user->username, $token_link));

    //verificar se o email foi enviado
    if(!$result) {

        return back()->with([
            'server_message' => $generic_message
        ]);

    }

    //guardar o token na base de dados
    $user->save();

    return back()->with([
        'server_message' => $generic_message
    ]);

}

    public function reset_password($token): View | RedirectResponse {
        //verificar se o token é valido
        $user = User::where('token', $token)->first();
        if(!$user) {
            return redirect()->route('login');
        }

        return view('auth.reset_password',['token' => $token]);
    }

    public function reset_password_update(Request $request):RedirectResponse {
        //form validation
        $request->validate(
            [
                'token' => 'required', // Token para redefinição de senha
                'new_password' => [
                    'required',
                    'min:8',
                    'max:32',
                    'regex:/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/', // Deve conter pelo menos uma letra e um número
                ],
                'new_password_confirmation' => 'required|same:new_password',
            ],
            [
                'token.required' => 'O token de redefinição de senha é obrigatório.',

                'new_password.required' => 'A nova senha é obrigatória.',
                'new_password.min' => 'A nova senha deve ter no mínimo :min caracteres.',
                'new_password.max' => 'A nova senha deve ter no máximo :max caracteres.',
                'new_password.regex' => 'A senha deve conter pelo menos uma letra e um número.',

                'new_password_confirmation.required' => 'A confirmação da nova senha é obrigatória.',
                'new_password_confirmation.same' => 'A confirmação da nova senha não corresponde.',
            ]
        );

        //verificar se o token é valido
        $user = User::where('token',$request->token)->first();
        if(!$user) {
            return redirect()->route('login');
        }

        //atualizar a senha do user na base de dados
        $user->password = bcrypt('$request->new_password');
        $user->token = null;
        $user->save();

        return redirect()->route('login')->with([
            'success' => true
        ]);
    }

    public function delete_account(Request $request)/* : RedirectResponse */ {
        //validção do form
        $request->validate(
            [
                'delete_confirmation' => 'required|in:ELIMINAR',
            ],
            [
                'delete_confirmation.required' => 'A confirmação é obrigatória.',
                'delete_confirmation.in' => 'É OBRIGATÓRIO ESCREVER A PALAVRA "ELIMINAR".',
            ]
        );


        //remover a conta de usuario com hard delete ou soft delete

        //softdelete
        $user = Auth::user();
        $user->delete();

        //harddelete
       /*  $user = Auth::user();
        $user->forceDelete(); */

        //logout
        Auth::logout();

        //redirect para login
        return redirect()->route('login')->with(['account_deleted' => true]);
    }

}
