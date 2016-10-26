import mkdirp from 'simple-mkdirp'
import { catchPlus, tap } from 'promise-toolbox'
import { join } from 'path'
import { readFile, writeFile } from 'fs-promise'
import { v4 as generateUuid } from 'uuid'

const __DEV__ = process.env.NODE_ENV !== 'production'

// TODO: transition from in-memory database to a real database system.
export class Store {
  constructor (app, { config: { datadir } }) {
    this._get = () => {
      const datafile = join(datadir, 'store.json')

      const promise = readFile(datafile)
        .then(JSON.parse)
        ::catchPlus({ code: 'ENOENT' }, () => ({}))
        ::tap(data => {
          app.on('stop', data =>
            mkdirp(datadir)
              .then(() => writeFile(datafile, JSON.stringify(data)))
          )
        })

      // Inline future accesses.
      this._get = () => promise

      return promise
    }

    this._types = {}
  }

  registerType (name, spec) {
    const types = this._types

    if (__DEV__ && name in types) {
      throw new Error(`type ${name} is already registered`)
    }

    types[name] = spec
  }

  async createObject (props) {
    const { type } = props
    if (__DEV__ && !type) {
      throw new Error('missing type')
    }

    const db = await this._get()
    const byType = db.byType || (db.byType = {})
    const collection = byType[type] || (byType[type] = {})

    let { id } = props
    if (!id) {
      props.id = id = generateUuid()
    }

    collection[id] = props
  }
}