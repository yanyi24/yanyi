const Validator = require('validator');
const isEmpty = require('./isEmpty');

module.exports = function validateRegisterInput(data) {  
	let errors = {};
	data.name = !isEmpty(data.name) ? data.name : '';
	data.email = !isEmpty(data.email) ? data.email : '';
	data.password = !isEmpty(data.password) ? data.password : '';
	data.password2 = !isEmpty(data.password2) ? data.password2 : '';

	if (!Validator.isLength(data.name, {min: 2, max: 20})) {
		errors.name = '名字的长度不能小于2位，不能大于20位！';
	}
	if (Validator.isEmpty(data.name)) {
		errors.name = '名字不能为空！';
	}

	if (!Validator.isEmail(data.email)) {
		errors.email = '邮箱不合规则！';
	}
	if (Validator.isEmpty(data.email)) {
		errors.email = '邮箱不能为空！';
	}

	if (Validator.isEmpty(data.password)) {
		errors.password = '密码不能为空！';
	}
	if (!Validator.isLength(data.password, {min: 6, max: 20})) {
		errors.password = '密码的长度不能小于6位，不能大于20位！';
	}

	if (Validator.isEmpty(data.password2)) {
		errors.password2 = '确认密码不能为空！';
	}
	if (!Validator.equals(data.password, data.password2)) {
		errors.password2 = '两次密码不一致，请重新输入！'
	}
	return {
		errors,
		isValid: isEmpty(errors)
	}
}

