<div class="login-form">
  <script type="text/JavaScript" src="JS/login_form.js"></script>
  <script type="text/JavaScript" src="JS/sha512.js"></script>
  <form action="includes/process_logon.php" method="post" name="login_form" accept-charset="UTF-8">
  <fieldset>
  <legend>Login</legend>
    <label for="username">User Name:</label>
    <input type="text" name="username" id="username" maxlength="50" placeholder="Username" />
    <label for="password">Password:</label>
    <input type="password" name="password" id="password" maxlength="50" placeholder="Password" />
    <input type="submit" name="login" value="Login" onclick="hashLoginCredentials(this.form, this.form.password);" />
  </fieldset>
  </form>
</div><!--closes class="login-form"-->
