'use strict'

// ===================================================================

var gulp = require('gulp')

var babel = require('gulp-babel')
var coffee = require('gulp-coffee')
var plumber = require('gulp-plumber')
var rimraf = require('rimraf')
var sourceMaps = require('gulp-sourcemaps')
var watch = require('gulp-watch')

var join = require('path').join

// ===================================================================

var SRC_DIR = join(__dirname, 'src')
var DIST_DIR = join(__dirname, 'dist')

var PRODUCTION = process.argv.indexOf('--production') !== -1

// ===================================================================

function src (patterns) {
  return PRODUCTION
    ? gulp.src(patterns, {
      base: SRC_DIR,
      cwd: SRC_DIR
    })
    : watch(patterns, {
      base: SRC_DIR,
      cwd: SRC_DIR,
      ignoreInitial: false,
      verbose: true
    })
      .pipe(plumber())
}

// ===================================================================

gulp.task(function clean (cb) {
  rimraf(DIST_DIR, cb)
})

gulp.task(function buildCoffee () {
  return src('**/*.coffee')
    .pipe(sourceMaps.init())
    .pipe(coffee({
      bare: true
    }))

    // Necessary to correctly compile generators.
    .pipe(babel())

    .pipe(sourceMaps.write('.'))
    .pipe(gulp.dest(DIST_DIR))
})

gulp.task(function buildEs6 () {
  return src([ '**/*.js', '!*.spec.js' ])
    .pipe(sourceMaps.init())
    .pipe(babel())
    .pipe(sourceMaps.write('.'))
    .pipe(gulp.dest(DIST_DIR))
})

// ===================================================================

gulp.task('build', gulp.series('clean', gulp.parallel('buildCoffee', 'buildEs6')))
