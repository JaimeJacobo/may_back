(this.webpackJsonpmay_front=this.webpackJsonpmay_front||[]).push([[0],{24:function(e,t,n){},25:function(e,t,n){},45:function(e,t,n){"use strict";n.r(t);var a=n(2),s=n.n(a),r=n(15),o=n.n(r),c=(n(24),n(4)),u=n(3),i=n(16),p=n(17),h=n(19),l=n(18),d=(n(25),n(6)),j=n.n(d),b=n(0),m=function(e){Object(h.a)(n,e);var t=Object(l.a)(n);function n(){var e;Object(i.a)(this,n);for(var a=arguments.length,s=new Array(a),r=0;r<a;r++)s[r]=arguments[r];return(e=t.call.apply(t,[this].concat(s))).state={inputNewUser:{username:"",password:""},user:{}},e}return Object(p.a)(n,[{key:"handleInput",value:function(e){var t=e.target,n=t.name,a=t.value;this.setState(Object(u.a)(Object(u.a)({},this.state),{},{inputNewUser:Object(u.a)(Object(u.a)({},this.state.inputNewUser),{},Object(c.a)({},n,a))}))}},{key:"submitSignUp",value:function(e){e.preventDefault(),j()({withCredentials:!0,method:"post",url:"https://may-front-back.herokuapp.com/auth/signup",data:{username:this.state.inputNewUser.username,password:this.state.inputNewUser.password}}).then((function(e){console.log(e)})).catch((function(e){console.log(e)}))}},{key:"submitLogIn",value:function(e){e.preventDefault(),j()({withCredentials:!0,method:"post",url:"https://may-front-back.herokuapp.com/auth/login",data:{username:this.state.inputNewUser.username,password:this.state.inputNewUser.password}}).then((function(e){console.log(e)})).catch((function(e){console.log(e)}))}},{key:"render",value:function(){var e=this;return Object(b.jsxs)("div",{className:"App",children:[Object(b.jsx)("h1",{children:"Componente App"}),Object(b.jsx)("h2",{children:"Create new user"}),Object(b.jsxs)("form",{onSubmit:function(t){e.submitSignUp(t)},children:[Object(b.jsx)("input",{type:"text",name:"username",placeholder:"Username",onChange:function(t){return e.handleInput(t)}}),Object(b.jsx)("input",{type:"text",name:"password",placeholder:"Password",onChange:function(t){return e.handleInput(t)}}),Object(b.jsx)("button",{children:"Create User"})]}),Object(b.jsx)("h2",{children:"Log in"}),Object(b.jsxs)("form",{onSubmit:function(t){e.submitLogIn(t)},children:[Object(b.jsx)("input",{type:"text",name:"username",placeholder:"Username",onChange:function(t){return e.handleInput(t)}}),Object(b.jsx)("input",{type:"text",name:"password",placeholder:"Password",onChange:function(t){return e.handleInput(t)}}),Object(b.jsx)("button",{children:"Log in"})]})]})}}]),n}(s.a.Component),f=function(e){e&&e instanceof Function&&n.e(3).then(n.bind(null,46)).then((function(t){var n=t.getCLS,a=t.getFID,s=t.getFCP,r=t.getLCP,o=t.getTTFB;n(e),a(e),s(e),r(e),o(e)}))};o.a.render(Object(b.jsx)(s.a.StrictMode,{children:Object(b.jsx)(m,{})}),document.getElementById("root")),f()}},[[45,1,2]]]);
//# sourceMappingURL=main.fb1e1fcf.chunk.js.map