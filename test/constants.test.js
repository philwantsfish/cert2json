const constants = require('../src/constants')


test('tag_to_type shoud handle context specific tags', () => {
    const tag0 = 0x80
    expect(constants.tag_to_type(tag0)).toBe('cont [ 0 ]')

    const tag1 = 0x81
    expect(constants.tag_to_type(tag1)).toBe('cont [ 1 ]')
})
