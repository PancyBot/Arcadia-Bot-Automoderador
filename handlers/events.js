const { glob } = require("glob");
const { promisify } = require("util");
const { Client } = require("discord.js");
const { Events } = require('../Validation/EventsNames')
const Ascii = require('ascii-table')
const globPromise = promisify(glob);


module.exports = async (client) => {

    const table = new Ascii("Eventos")
	table.setHeading('Eventos', ' Load status');



    (await globPromise(`${process.cwd()}/events/*/*.js`)).map(async file => {

        const event = require(file);

        if(!Events.includes(event.name) || !event.name) {
            const L = file.split('/')
            await table.addRow(`${event.name || "No encontrado"}`, `⛔ El nombre del evento es invalido o no se encontro: ${L[6] + `/` + L[7]}`)
            return;
        };
        if(event.once) {
            client.once(event.name, (...args) => event.execute(...args, client))
        } else {
            client.on(event.name, (...args) => event.execute(...args, client))
        }
        await table.addRow(event.name, "Cargado")
    })

    console.log(table.toString())


}