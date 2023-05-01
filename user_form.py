from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

class EmailFormMixin:
    email = StringField(validators=[DataRequired(), Email()])

class PasswordFormMixin:
    password = PasswordField(validators=[DataRequired()])

class SecurityQuestionFormMixin:
    security_question = StringField(validators=[DataRequired()])
    security_answer = StringField(validators=[DataRequired()])

class RegistrationForm(FlaskForm, EmailFormMixin, PasswordFormMixin, SecurityQuestionFormMixin):
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm, EmailFormMixin, PasswordFormMixin):
    submit = SubmitField('Login')

class PasswordResetForm(FlaskForm, EmailFormMixin, SecurityQuestionFormMixin):
    new_password = PasswordField(validators=[DataRequired()])
    confirm_password = PasswordField(validators=[DataRequired()])

    def validate_confirm_password(self, field):
        if self.new_password.data != field.data:
            raise ValidationError('Passwords do not match.')

    submit = SubmitField('Reset Password')
