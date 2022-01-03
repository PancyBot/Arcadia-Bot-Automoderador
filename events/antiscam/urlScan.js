
const { Client, Message, MessageEmbed } = require('discord.js');
const fetch = require('node-fetch');
const uploadFile = "https://www.virustotal.com/api/v3/files",
    fileScanInfo = "https://www.virustotal.com/api/v3/files",
    scanURL = "https://www.virustotal.com/api/v3/urls",
    scanDomain = "https://www.virustotal.com/api/v3/domains",
    scanIP = "https://www.virustotal.com/api/v3/ip_addresses";


module.exports = {
    name: 'messageCreate',

    /**
     * @param {Message} message 
     * @param {Client} client 
     */
    async execute(message, client) {

        if(message.content.includes("www")) {
            const messagetxt = message.content;
            const regex = /(https+["://"]+www+(\.[a-zA-Z0-9-]+\.com)+)/gm
            const dominian = messagetxt.match(regex)
            console.log('0.1')
            console.log(dominian)
            const options = {
                method: 'POST',
                headers: {
                  Accept: 'application/json',
                  'x-apikey': process.env.API,
                  'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({url: dominian[0]})
              };
            await fetch(scanURL, options).then(res => res.json()).then(async json => {
                console.log('1')
                console.log(json)
                if(json.error) return message.channel.send({ content: json.error.code})
                const regex = /(-([0-9]+[0-9]))/gm
                const  reportIdC = json.data.id
                const reportIdC2 = reportIdC.replace('u-', '')
                const reportId = reportIdC2.replace(regex, '')
                if(!reportId) return message.channel.send({ content: 'Error al analizar la URL'})
                await fetch(`${scanURL}/${reportId}`, {
                    method: 'GET',
                    headers: { 'Content-Type': 'application/json', 'x-apikey': process.env.API }
                }).then(res2 => res2.json()).then(async json2 => {
                    console.log(2)
                    console.log(json2)
                    if(json.error) {
                        console.log('Ocurrio un error reintentando en 15s')
                        setTimeout(async () => {
                            await fetch(`${scanURL}/${reportId}`, {
                                method: 'GET',
                                headers: { 'Content-Type': 'application/json', 'x-apikey': process.env.API }
                            }).then(res => res.json()).then(async json => {
                                console.log(json2.data.attributes.last_analysis_stats)
                                console.log(json2.data.attributes.last_analysis_results)
                                if(!json2.data.attributes.last_analysis_stats) return;
                                const malucious = json2.data.attributes.last_analysis_stats.malicious;
                                const suspicious = json2.data.attributes.last_analysis_stats.suspicious;
                                if(malucious || suspicious) {
                                    message.delete()
                                    const author = message.author
                                    const { guild } = message
                                    const EmbedBan = new MessageEmbed()
                                    .setTitle('Usuario baneado')
                                    .addField('Moderador', client.user.tag)
                                    .addField('Usuario', author.tag)
                                    .addField('Razón', 'Publicar links maliciosos')
                                    .setTimestamp()
            
                                    author.send({ embeds: [EmbedBan] })
                                    await client.channels.cache.get('834149620937523240').send({ embeds: [EmbedBan] })
                                    await guild.members.cache.get(author.id).ban({ reason: 'Publicar links maliciosos' })
            
                                }           
                            })
                        }, 15000)
                    }
                    console.log(json2.data.attributes.last_analysis_stats)
                    console.log(json2.data.attributes.last_analysis_results)
                    if(!json2.data.attributes.last_analysis_stats) return;
                    const malucious = json2.data.attributes.last_analysis_stats.malicious;
                    const suspicious = json2.data.attributes.last_analysis_stats.suspicious;
                    if(malucious || suspicious) {
                        message.delete()
                        const author = message.author
                        const { guild } = message
                        const EmbedBan = new MessageEmbed()
                        .setTitle('Usuario baneado')
                        .addField('Moderador', client.user.tag)
                        .addField('Usuario', author.tag)
                        .addField('Razón', 'Publicar links maliciosos')
                        .setTimestamp()

                        await guild.members.cache.get(author.id).ban({ reason: 'Publicar links maliciosos' }).catch(err => {
                            console.log(err)
                            return;   
                        })
                        await author.send({ embeds: [EmbedBan.addField('Link para apelar:', '[Formulario](https://forms.gle/jQbJLPHSNopsZmXz5)')] }).catch(err => console.log(err))
                        await message.channel.send({ embeds: [EmbedBan] })
                        await client.channels.cache.get('834149620937523240').send({ embeds: [EmbedBan] })
                    }

                })
            })
        } else if(message.content.includes("https://")) {
            const messagetext = message.content;
            const regex = /(https+["://"]+([a-zA-Z0-9-]+\.com))/gm
            const dominianregex = messagetext.match(regex)
            if(!dominianregex[0]) return;
            const dominian = dominianregex[0].replace('https://', '')
            console.log(dominian)
            console.log('0.2')
            await fetch(`${scanDomain}/${dominian}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json', 'x-apikey': process.env.API }
            }).then(res => res.json()).then(async json => {
                console.log(json.data.attributes.last_analysis_stats)
                console.log(json.data.attributes.last_analysis_results)
                if(!json.data.attributes.last_analysis_stats) return;
                const malucious = json.nodedata.attributes.last_analysis_stats.malicious;
                const suspicious = json.data.attributes.last_analysis_stats.suspicious;
                if(malucious || suspicious) {
                    message.delete()
                    const author = message.author
                    const { guild } = message
                    const EmbedBan = new MessageEmbed()
                    .setTitle('Usuario baneado')
                    .addField('Moderador', client.user.tag)
                    .addField('Usuario', author.tag)
                    .addField('Razón', 'Publicar links maliciosos')
                    .setTimestamp()

                    await guild.members.cache.get(author.id).ban({ reason: 'Publicar links maliciosos' }).catch(err => {
                        console.log(err)
                        return;   
                    })
                    await author.send({ embeds: [EmbedBan.addField('Link para apelar:', '[Formulario](https://forms.gle/jQbJLPHSNopsZmXz5)')] }).catch(err => console.log(err))
                    await client.channels.cache.get('834149620937523240').send({ embeds: [EmbedBan] })
                    await guild.members.cache.get(author.id).ban({ reason: 'Publicar links maliciosos' })

                }

            })

        }

    }
}

//ddba5dd927df01eff93ff3ead3a1f7e6d9f0aa9e7778b8c33ad281d066ef06ec
//u-ddba5dd927df01eff93ff3ead3a1f7e6d9f0aa9e7778b8c33ad281d066ef06ec-1641227730