import * as models from '../models/index'

async function run() {
  const [products] = await models.sequelize.query(
    'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
    { replacements: { criteria: '%apple%' } }
  )
  console.log('Products found:', products.length)
}
run().catch(console.error)
