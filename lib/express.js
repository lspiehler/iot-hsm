var createError = require('http-errors');
var express = require('express');
const multer  = require('multer')
var exphbs  = require('express-handlebars');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const fs = require('fs')
const config = require('../config');

var indexRouter = require('../routes/index');
var usersRouter = require('../routes/users');

var app = express();

var helpers = {
  ifEquals: function(arg1, arg2, options) {
    return (arg1 == arg2) ? options.fn(this) : options.inverse(this);
  }
}

// view engine setup
app.engine('.hbs', exphbs({ defaultLayout: 'main', extname: '.hbs' , helpers: helpers}));
app.set('views', path.join(__dirname, '../views'));
app.set('view engine', '.hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/js/bootstrap', express.static('./node_modules/bootstrap/dist/js'));
app.use('/js/dropzone', express.static('./node_modules/dropzone/dist/min'));
app.use('/js/jquery', express.static('./node_modules/jquery/dist'));
app.use('/css/bootstrap', express.static('./node_modules/bootstrap/dist/css'));

// disk storage engine gives you full control on storing files to disk.
const storage = multer.diskStorage({

    destination: (req, file, cb) => {
        cb(null, './uploads');
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname.replace(/\.[^/.]+$/, "") + '-' + Date.now() + path.extname(file.originalname));
    }
});

// set up upload method
const upload = multer({
    storage,
    limits: {
        fileSize: 1000000, // max size of files to upload / bytes        
        files:10
    },
    fileFilter: function (req, file, cb) {
        const fileTypes = /jpeg|jpg|png|pdf|json/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimeType = fileTypes.test(file.mimetype);

        if (extname && mimeType) {
            return cb(null, true);
        } else {
            return cb('File type not allowed ');
        }

    }

}).any();

app.post('/google-auth-upload', (req, res) => {

    // call upload method
    upload(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            console.log(err);
        } else if (err) {
            console.log(err);
        }
        // console.log(req.files);
        fs.rename(__dirname + '/../' + req.files[0].path, __dirname + '/../state/' + config.GOOGLE_APPLICATION_CREDENTIALS.split('/').pop(), function (err) {
            if (err) {
                res.status(500).send(err);
            } else {
                fs.chmod(__dirname + '/../state/' + config.GOOGLE_APPLICATION_CREDENTIALS.split('/').pop(), 0o600, (err) => {
                    if (err) {
                        res.status(500).send(err);
                    } else {
                        process.env['GOOGLE_APPLICATION_CREDENTIALS'] = config.GOOGLE_APPLICATION_CREDENTIALS;
                        res.status(200).send('files uploaded');
                    }
                });
            }
        });
        // fs.rename(req.files[0].path, './uploads/google-credentials.json', function (err) {
    });
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
